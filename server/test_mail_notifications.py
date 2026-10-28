import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch


os.environ.setdefault("AGENT_AUTH_TOKEN", "a" * 32)
os.environ.setdefault("DASHBOARD_JWT_SECRET", "b" * 32)

from server import main_server


def _vuln(product, *cves):
    return {"product": product, "version": "1.0",
            "cves": [{"cve_id": cve_id, "cvss_score": score} for cve_id, score in cves]}


class DetectNewItemsTests(unittest.TestCase):
    def test_new_host_reports_its_cves_but_not_its_users_or_updates(self):
        events, fields = main_server._detect_new_items(
            {}, vulns=[_vuln("nginx", ("CVE-2026-0001", 9.8))],
            update_check={"ok": True, "items": [{"name": "nginx", "available": "1.26"}]},
            logged_users=[{"username": "alice"}])
        self.assertEqual([t for t, _ in events], ["new_cves"])
        self.assertEqual(fields["notify_known.users"], ["alice"])
        self.assertEqual(fields["notify_known.updates"], ["nginx|1.26"])

    def test_existing_host_without_memory_uses_stored_state_as_baseline(self):
        existing = {"_id": "x", "vulnerabilities": [_vuln("nginx", ("CVE-2026-0001", 9.8))],
                    "logged_users": [{"username": "alice"}]}
        events, _ = main_server._detect_new_items(
            existing, vulns=[_vuln("nginx", ("CVE-2026-0001", 9.8), ("CVE-2026-0002", 7.0))],
            logged_users=[{"username": "alice"}, {"username": "bob"}])
        found = {t: [i.get("cve_id") or i.get("username") for i in items] for t, items in events}
        self.assertEqual(found, {"new_cves": ["CVE-2026-0002"], "new_local_users": ["bob"]})

    def test_memory_is_cumulative_so_flapping_items_are_reported_once(self):
        existing = {"_id": "x", "notify_known": {"users": ["alice", "bob"]},
                    "logged_users": [{"username": "alice"}]}
        events, fields = main_server._detect_new_items(
            existing, logged_users=[{"username": "alice"}, {"username": "Bob"}])
        self.assertEqual(events, [])
        self.assertEqual(sorted(fields["notify_known.users"]), ["alice", "bob"])

    def test_failed_update_check_is_ignored(self):
        events, fields = main_server._detect_new_items(
            {"_id": "x"}, update_check={"ok": False, "items": []})
        self.assertEqual((events, fields), ([], {}))

    def test_new_available_version_of_known_package_is_new(self):
        existing = {"_id": "x", "notify_known": {"updates": ["mozilla.firefox|121.0"]}}
        events, _ = main_server._detect_new_items(existing, update_check={"ok": True, "items": [
            {"name": "Firefox", "id": "Mozilla.Firefox", "available": "122.0"}]})
        self.assertEqual(events[0][0], "new_updates")
        self.assertEqual(events[0][1][0]["available"], "122.0")


class MoreDetectionTests(unittest.TestCase):
    def test_epss_crossing_threshold_on_known_cve_is_reported(self):
        cve = lambda epss: [{"product": "nginx", "cves": [
            {"cve_id": "CVE-1", "cvss_score": 5.0, "epss_score": epss}]}]
        existing = {"_id": "x", "notify_known": {"cves": ["cve-1|nginx"], "epss": []}}
        events, _ = main_server._detect_new_items(existing, vulns=cve(0.3))
        self.assertEqual([t for t, _ in events], ["high_epss"])
        events, _ = main_server._detect_new_items(existing, vulns=cve(0.05))
        self.assertEqual(events, [])

    def test_open_ports_baseline_then_new_port(self):
        events, _ = main_server._detect_new_items({"_id": "x"}, open_ports=[22])
        self.assertEqual(events, [])
        events, _ = main_server._detect_new_items({"_id": "x", "open_ports": [22]}, open_ports=[22, 3389])
        self.assertEqual(events, [("new_open_ports", [{"port": 3389, "service": "RDP"}])])

    def _changes(self, existing, software, compliance=None):
        info = {"os": "Linux"}
        with patch.object(main_server, "mongo", MagicMock()) as mongo:
            mongo.db.compliance_config.find_one.return_value = None
            return dict(main_server._detect_state_changes(
                existing, os_str="Linux", compliance=compliance or {}, software_list=software,
                host_info=info))

    def test_first_full_report_is_a_new_host(self):
        self.assertEqual(self._changes({"_id": "x", "last_seen": 1}, [])["new_hosts"], [{"os": "Linux"}])

    def test_software_installed_removed_and_updated(self):
        existing = {"received_at": "t", "software": [{"product": "nginx", "version": "1.18"},
                                                     {"product": "curl", "version": "7"}]}
        changes = self._changes(existing, [{"product": "nginx", "version": "1.24"},
                                           {"product": "git", "version": "2"}])["software_changes"]
        self.assertEqual({(c["change"], c["product"]) for c in changes},
                         {("installed", "git"), ("removed", "curl"), ("updated", "nginx")})

    def test_partial_inventory_is_not_reported_as_uninstalls(self):
        software = [{"product": f"p{i}", "version": "1"} for i in range(60)]
        changes = self._changes({"received_at": "t", "software": software}, software[:10])
        self.assertNotIn("software_changes", changes)

    def test_compliance_rule_going_from_pass_to_fail_is_drift(self):
        existing = {"received_at": "t", "os": "Linux", "compliance": {"firewall_enabled": True}}
        drift = self._changes(existing, [], {"firewall_enabled": False})["compliance_drift"]
        self.assertEqual([d["rule_id"] for d in drift], ["firewall_enabled"])

    def test_offline_host_reported_once_then_back_online(self):
        now = datetime(2026, 10, 28, 12, 0)
        prefs = main_server._normalized_preferences({"role": "codir", "notifications": {
            "agent_offline": {"enabled": True, "hours": 4}}})
        seen = now - timedelta(hours=5)
        agents = [{"hostname": "srv", "last_seen": seen}, {"hostname": "pc", "last_seen": now}]
        offline, back, state = main_server._offline_changes({}, prefs, agents, now)
        self.assertEqual([r[0] for r in offline], ["srv"])
        user = {"notify_state": {"offline": state}}
        self.assertEqual(main_server._offline_changes(user, prefs, agents, now)[0], [])
        agents[0]["last_seen"] = now
        offline, back, state = main_server._offline_changes(user, prefs, agents, now)
        self.assertEqual(([r[0] for r in back], state), (["srv"], []))

    def test_scan_health_alerts_at_most_once_a_day(self):
        store = {}
        settings = MagicMock()
        settings.find_one.side_effect = lambda q: store.get("doc")
        settings.update_one.side_effect = lambda q, u, upsert=False: store.setdefault("doc", {}).update(u["$set"])
        mongo = MagicMock()
        mongo.db.settings = settings
        with patch.object(main_server, "mongo", mongo), \
                patch.object(main_server, "_queue_notifications") as queue:
            main_server._track_cve_scan_health("srv", False, "Quota épuisé")
            main_server._track_cve_scan_health("srv", True, None)
            main_server._track_cve_scan_health("srv", False, "Quota épuisé")
            self.assertEqual(queue.call_count, 1)
            store["doc"]["alerted_at"] = datetime.utcnow() - timedelta(hours=25)
            main_server._track_cve_scan_health("srv", False, "Quota épuisé")
            self.assertEqual(queue.call_count, 2)

    def test_notification_failure_never_raises(self):
        broken = MagicMock()
        broken.db.settings.find_one.side_effect = RuntimeError("mongo down")
        broken.db.compliance_config.find_one.side_effect = RuntimeError("mongo down")
        with patch.object(main_server, "mongo", broken):
            main_server._track_cve_scan_health("srv", False, "x")
            self.assertEqual(main_server._detect_state_changes(
                {"received_at": "t", "compliance": {"a": 1}}, os_str="Linux",
                compliance={"a": 2}, software_list=[], host_info={}), [])


class DigestTests(unittest.TestCase):
    def _prefs(self, role="admin", **notifications):
        return main_server._normalized_preferences({"role": role, "notifications": notifications})

    def test_cves_below_user_threshold_are_left_out(self):
        prefs = self._prefs(new_cves={"enabled": True, "min_severity": "critical"})
        events = [{"type": "new_cves", "hostname": "srv", "items": [
            {"cve_id": "CVE-1", "product": "p", "cvss_score": 9.1},
            {"cve_id": "CVE-2", "product": "p", "cvss_score": 8.9}]}]
        subject, sections = main_server._digest_for_user(prefs, events)
        self.assertIn("1 nouvelle(s) CVE", subject)
        self.assertEqual([row[1] for row in sections[0][2]], ["CVE-1"])

    def test_role_without_access_never_receives_cves(self):
        prefs = self._prefs(role="codir", new_cves={"enabled": True})
        events = [{"type": "new_cves", "hostname": "srv",
                   "items": [{"cve_id": "CVE-1", "product": "p", "cvss_score": 10}]}]
        self.assertFalse(prefs["new_cves"]["enabled"])
        self.assertIsNone(main_server._digest_for_user(prefs, events))

    def test_nothing_enabled_gives_no_mail(self):
        events = [{"type": "new_local_users", "hostname": "srv", "items": [{"username": "eve"}]}]
        self.assertIsNone(main_server._digest_for_user(self._prefs(), events))

    def test_html_body_escapes_agent_supplied_values(self):
        _, html_body = main_server._mail_render("T", "i", [("S", ["Hôte"], [["<script>x</script>"]], None)])
        self.assertIn("&lt;script&gt;", html_body)
        self.assertNotIn("<script>", html_body)


class ComplianceScheduleTests(unittest.TestCase):
    def test_report_is_due_after_the_chosen_number_of_days(self):
        now = datetime(2026, 10, 28, 8, 0)
        def prefs(last):
            return main_server._normalized_preferences({"role": "codir", "notifications": {
                "compliance_report": {"enabled": True, "every_days": 7, "last_sent_at": last}}})
        self.assertTrue(main_server._compliance_report_due(prefs(None), now))
        self.assertFalse(main_server._compliance_report_due(prefs(now - timedelta(days=6)), now))
        self.assertTrue(main_server._compliance_report_due(prefs(now - timedelta(days=7)), now))

    def test_frequency_is_bounded(self):
        prefs = main_server._normalized_preferences({"role": "admin", "notifications": {
            "compliance_report": {"enabled": True, "every_days": 1000}}})
        self.assertEqual(prefs["compliance_report"]["every_days"], 90)


class SendMailTests(unittest.TestCase):
    def _cfg(self, security):
        return {"host": "smtp.example.com", "port": 587, "security": security, "username": "u",
                "password": "p", "from_addr": "heimdall@example.com", "verify_tls": True}

    def test_starttls_logs_in_and_sends(self):
        smtp = MagicMock()
        with patch("smtplib.SMTP", return_value=smtp) as factory:
            main_server._send_mail(self._cfg("starttls"), "to@example.com", "Sujet", "texte", "<p>html</p>",
                                   [("r.pdf", b"%PDF", "application/pdf")])
        factory.assert_called_once_with("smtp.example.com", 587, timeout=30)
        session = smtp   # smtplib : __enter__ renvoie l'objet lui-même
        session.starttls.assert_called_once()
        session.login.assert_called_once_with("u", "p")
        message = session.send_message.call_args[0][0]
        self.assertEqual(message["To"], "to@example.com")
        self.assertEqual([p.get_filename() for p in message.iter_attachments()], ["r.pdf"])

    def test_implicit_tls_uses_smtp_ssl(self):
        with patch("smtplib.SMTP_SSL", return_value=MagicMock()) as factory:
            main_server._send_mail(self._cfg("ssl"), "to@example.com", "S", "t", "<p>h</p>")
        factory.assert_called_once()


if __name__ == "__main__":
    unittest.main()

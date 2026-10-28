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

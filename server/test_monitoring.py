import os
import unittest
from datetime import datetime, timedelta


os.environ.setdefault("AGENT_AUTH_TOKEN", "a" * 32)
os.environ.setdefault("DASHBOARD_JWT_SECRET", "b" * 32)

from server import main_server


NOW = datetime(2026, 10, 30, 12, 0)


def _vuln(product, *cves):
    return {"product": product, "version": "1.0",
            "cves": [{"cve_id": i, "cvss_score": s, "epss_score": e, "date_published": d} for i, s, e, d in cves]}


class WatchlistTests(unittest.TestCase):
    def test_tokens_ignore_generic_words(self):
        self.assertEqual(main_server._watch_tokens("Apache Tomcat"), ["apache", "tomcat"])
        self.assertEqual(main_server._watch_tokens("Microsoft Visual C++ 2015 Redistributable (x64)"), [])
        self.assertEqual(main_server._watch_tokens("Notepad++"), ["notepad++"])

    def test_only_recent_critical_or_exploited_cves_are_watched(self):
        vulns = [
            _vuln("Apache Tomcat", ("CVE-1", 9.8, 0.01, "2024-01-01")),          # critique
            _vuln("OpenSSL", ("CVE-2", 7.5, 0.30, "2023-01-01")),                # exploitation probable
            _vuln("Notepad++", ("CVE-3", 7.8, 0.01, "2026-10-20")),              # récente et élevée
            _vuln("Firefox", ("CVE-4", 6.1, 0.01, "2026-10-20")),                # récente mais moyenne
            _vuln("Zoom", ("CVE-5", 8.8, 0.01, "2023-01-01")),                   # ancienne, non exploitée
        ]
        names = [p["name"] for p in main_server._hot_products(vulns, NOW)]
        self.assertEqual(names, ["Apache Tomcat", "OpenSSL", "Notepad++"])


class EventTests(unittest.TestCase):
    def test_untrusted_input_is_validated_and_bounded(self):
        self.assertIsNone(main_server._sanitize_security_event({"rule": "x; drop", "severity": "high"}, NOW))
        self.assertIsNone(main_server._sanitize_security_event({"rule": "new_service", "severity": "apocalyptic"}, NOW))
        ev = main_server._sanitize_security_event({
            "rule": "new_service", "severity": "high", "title": "t" * 500,
            "details": {f"k{i}": "v" * 5000 for i in range(50)}, "observed_at": "2999-01-01T00:00:00"}, NOW)
        self.assertEqual(len(ev["title"]), 200)
        self.assertEqual(len(ev["details"]), 20)
        self.assertTrue(all(len(v) <= 1000 for v in ev["details"].values()))
        self.assertEqual(ev["observed_at"], NOW)          # date future ramenée à maintenant

    def test_event_touching_a_vulnerable_product_is_linked_and_raised(self):
        hot = main_server._hot_products([_vuln("Notepad++", ("CVE-3", 7.8, 0.01, "2026-10-20"))], NOW)
        ev = main_server._sanitize_security_event({
            "rule": "new_scheduled_task", "severity": "medium", "title": "Tâche",
            "details": {"command": r"C:\Users\bob\AppData\Roaming\Notepad++\updater\gup.exe"}}, NOW)
        ev = main_server._enrich_with_cves(ev, hot)
        self.assertEqual(ev["severity"], "high")
        self.assertEqual(ev["related_cves"][0]["cves"], ["CVE-3"])

    def test_unrelated_event_is_unchanged(self):
        hot = main_server._hot_products([_vuln("Apache Tomcat", ("CVE-1", 9.8, 0.5, "2026-10-20"))], NOW)
        ev = main_server._sanitize_security_event({"rule": "new_service", "severity": "medium", "title": "t",
                                                   "details": {"image": "/usr/sbin/cron"}}, NOW)
        self.assertEqual(main_server._enrich_with_cves(ev, hot)["severity"], "medium")

    def test_agent_watchlist_alert_is_not_raised_twice(self):
        hot = main_server._hot_products([_vuln("Apache Tomcat", ("CVE-1", 9.8, 0.5, "2026-10-20"))], NOW)
        ev = main_server._sanitize_security_event({"rule": "vulnerable_app_spawns_shell", "severity": "high",
                                                   "title": "t", "details": {"parent_image": "/opt/tomcat/bin/java",
                                                                             "watchlist_match": "Apache Tomcat"}}, NOW)
        self.assertEqual(main_server._enrich_with_cves(ev, hot)["severity"], "high")


class MailDigestTests(unittest.TestCase):
    def test_security_alerts_respect_the_user_minimum_severity(self):
        prefs = main_server._normalized_preferences({"role": "inspection_logs", "notifications": {
            "security_events": {"enabled": True, "min_severity": "high"}}})
        events = [{"type": "security_events", "hostname": "srv", "items": [
            {"rule": "a", "severity": "critical", "title": "Shell inversé", "summary": "bash -i"},
            {"rule": "b", "severity": "low", "title": "Nouveau logiciel", "summary": "x"}]}]
        subject, sections = main_server._digest_for_user(prefs, events)
        self.assertIn("1 alerte(s) de surveillance", subject)
        self.assertEqual([row[2] for row in sections[0][2]], ["Shell inversé"])

    def test_codir_cannot_receive_security_alerts(self):
        prefs = main_server._normalized_preferences({"role": "codir", "notifications": {
            "security_events": {"enabled": True}}})
        self.assertFalse(prefs["security_events"]["enabled"])


if __name__ == "__main__":
    unittest.main()

import json
import os
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import requests


os.environ.setdefault("AGENT_AUTH_TOKEN", "a" * 32)
os.environ.setdefault("DASHBOARD_JWT_SECRET", "b" * 32)

from server import main_server


class FakeSettings:
    def __init__(self):
        self.docs = {}

    def find_one(self, query, *args, **kwargs):
        return self.docs.get(query["_id"])

    def replace_one(self, query, doc, upsert=False):
        self.docs[query["_id"]] = dict(doc)

    def delete_one(self, query):
        self.docs.pop(query["_id"], None)


class FakeCache:
    """cve_search_cache : seuls les produits listés sont en cache."""
    def __init__(self, cached=()):
        self.cached = {p.lower() for p in cached}

    def find_one(self, query, *args, **kwargs):
        product = query["product"].split("|")[0]
        return {"cves": []} if product in self.cached else None

    def update_one(self, *args, **kwargs):
        pass


class FakeApi:
    """Remplace requests.request et compte les appels réellement envoyés."""
    def __init__(self, status, text="", headers=None, quota=None):
        self.status, self.text, self.headers, self.quota = status, text, headers or {}, quota
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append(url)
        response = requests.Response()
        if url.endswith("/account/endpoints/checkin"):
            response.status_code, response._content = 200, b"{}"
        elif url.endswith("/account/quota") and self.quota is not None:
            response.status_code, response._content = 200, json.dumps(self.quota).encode()
        else:
            response.status_code, response._content = self.status, self.text.encode()
            response.headers.update(self.headers)
        return response

    def searches(self):
        return sum(1 for url in self.calls if "/cves/search" in url)


SOFTWARE = [{"product": f"logiciel{i}", "version": "1.0"} for i in range(50)]


class CircuitBreakerTests(unittest.TestCase):
    def setUp(self):
        main_server._cve_block_state.update(loaded=False, doc=None)
        self.settings = FakeSettings()
        self.mongo = SimpleNamespace(db=SimpleNamespace(settings=self.settings, cve_search_cache=FakeCache()))
        patches = [patch.object(main_server, "mongo", self.mongo),
                   patch.object(main_server, "_api_version_search_enabled", return_value=False),
                   patch.object(main_server, "_claim_cve_query", return_value=True)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def correlate(self, api, key="cle-a", software=SOFTWARE):
        with patch.object(main_server.requests, "request", api):
            status = {}
            vulns, complete = main_server.correlate_vulnerabilities(
                software, key, return_status=True, hostname="srv", status=status)
            return complete, status.get("reason")

    def test_exhausted_quota_stops_after_one_request(self):
        api = FakeApi(429, "Quota journalier dépassé")
        complete, reason = self.correlate(api)
        self.assertFalse(complete)
        self.assertEqual(api.searches(), 1)          # et non 50
        self.assertIn("quota journalier", reason.lower())
        self.correlate(api)                          # rapport suivant
        self.assertEqual(api.searches(), 1)
        until = self.settings.docs["cve_api_block"]["until"]
        self.assertEqual((until.hour, until.minute), (0, 5))   # reprise après minuit UTC

    def test_unknown_key_stops_and_is_not_retried_for_hours(self):
        api = FakeApi(401, "Clé API inconnue")
        self.correlate(api)
        self.correlate(api)
        self.assertEqual(api.searches(), 1)
        until = self.settings.docs["cve_api_block"]["until"]
        self.assertGreater(until - main_server.datetime.utcnow(), timedelta(hours=5))

    def test_new_key_is_tried_immediately(self):
        api = FakeApi(401, "Clé API inconnue")
        self.correlate(api, key="ancienne")
        self.correlate(api, key="nouvelle")
        self.assertEqual(api.searches(), 2)

    def test_requests_resume_after_expiry(self):
        api = FakeApi(429, "Quota journalier dépassé")
        self.correlate(api)
        main_server._cve_block_state["doc"]["until"] = main_server.datetime.utcnow() - timedelta(seconds=1)
        self.correlate(api)
        self.assertEqual(api.searches(), 2)

    def test_retry_after_header_is_respected(self):
        api = FakeApi(429, "Too Many Requests", headers={"Retry-After": "120"})
        self.correlate(api)
        delay = self.settings.docs["cve_api_block"]["until"] - main_server.datetime.utcnow()
        self.assertTrue(timedelta(seconds=100) < delay <= timedelta(seconds=120))

    def test_block_survives_a_restart(self):
        self.correlate(FakeApi(429, "Quota journalier dépassé"))
        main_server._cve_block_state.update(loaded=False, doc=None)   # nouveau processus
        api = FakeApi(200, json.dumps({"results": []}))
        self.correlate(api)
        self.assertEqual(api.searches(), 0)

    def test_cached_products_are_still_analysed_while_blocked(self):
        self.mongo.db.cve_search_cache = FakeCache(cached=["logiciel0"])
        self.correlate(FakeApi(429, "Quota journalier dépassé"))
        api = FakeApi(200, json.dumps({"results": []}))
        complete, reason = self.correlate(api, software=SOFTWARE[:1])
        self.assertTrue(complete)
        self.assertEqual(api.searches(), 0)

    @patch.object(main_server, "SERVER_CVE_API_KEY", "cle-a")
    def test_quota_refill_lifts_the_block(self):
        self.correlate(FakeApi(429, "Quota journalier dépassé"))
        with patch.object(main_server.requests, "request", FakeApi(200, quota={"daily_remaining": 0, "credits": 0})):
            main_server._fetch_cve_quota()
        self.assertIsNotNone(main_server._cve_block_active("cle-a"))
        with patch.object(main_server.requests, "request", FakeApi(200, quota={"daily_remaining": 0, "credits": 500})):
            main_server._fetch_cve_quota()
        self.assertIsNone(main_server._cve_block_active("cle-a"))

    def test_manual_clear_allows_one_new_attempt(self):
        api = FakeApi(429, "Quota journalier dépassé")
        self.correlate(api)
        main_server.cve_block_clear("analyse lancée à la main")
        self.correlate(api)
        self.assertEqual(api.searches(), 2)


if __name__ == "__main__":
    unittest.main()

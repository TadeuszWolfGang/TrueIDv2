import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SYNC_DIR = REPO_ROOT / "integrations" / "sycope"

sys.path.insert(0, str(SYNC_DIR))

from trueid_api import TrueIdApi


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload
        self.raise_called = False

    def raise_for_status(self):
        self.raise_called = True

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self, responses=None):
        self.headers = {}
        self.responses = list(responses or [])
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append({"url": url, "params": params, "timeout": timeout})
        return self.responses.pop(0)


class TrueIdApiTests(unittest.TestCase):
    def test_sets_x_api_key_header(self):
        session = FakeSession()

        TrueIdApi(
            session=session,
            host="http://trueid.local",
            api_key="tid_example_key",
        )

        self.assertEqual(session.headers["X-API-Key"], "tid_example_key")
        self.assertNotIn("Authorization", session.headers)

    def test_get_active_mappings_accepts_plain_list_payload(self):
        response = FakeResponse([{"ip": "10.50.0.100", "user": "jan.test"}])
        session = FakeSession([response])
        api = TrueIdApi(session=session, host="http://trueid.local")

        data = api.get_active_mappings()

        self.assertEqual(data, [{"ip": "10.50.0.100", "user": "jan.test"}])
        self.assertTrue(response.raise_called)
        self.assertEqual(
            session.calls[0],
            {"url": "http://trueid.local/api/v1/mappings", "params": None, "timeout": 30},
        )

    def test_get_active_mappings_unwraps_data_envelope(self):
        response = FakeResponse({"data": [{"ip": "10.50.0.100", "user": "jan.test"}]})
        session = FakeSession([response])
        api = TrueIdApi(session=session, host="http://trueid.local")

        data = api.get_active_mappings()

        self.assertEqual(data, [{"ip": "10.50.0.100", "user": "jan.test"}])

    def test_get_events_since_passes_since_and_unwraps_data_envelope(self):
        response = FakeResponse({"data": [{"id": 1, "ip": "10.50.0.100"}]})
        session = FakeSession([response])
        api = TrueIdApi(session=session, host="http://trueid.local")

        data = api.get_events_since(1712148627)

        self.assertEqual(data, [{"id": 1, "ip": "10.50.0.100"}])
        self.assertEqual(
            session.calls[0],
            {
                "url": "http://trueid.local/api/v1/events",
                "params": {"since": 1712148627},
                "timeout": 30,
            },
        )


if __name__ == "__main__":
    unittest.main()

import os
import sys
import unittest
from pathlib import Path

import requests


REPO_ROOT = Path(__file__).resolve().parents[3]
SYNC_DIR = REPO_ROOT / "integrations" / "sycope"

sys.path.insert(0, str(SYNC_DIR))

from trueid_api import TrueIdApi


@unittest.skipUnless(
    os.getenv("TRUEID_TEST_URL") and os.getenv("TRUEID_TEST_API_KEY"),
    "Set TRUEID_TEST_URL and TRUEID_TEST_API_KEY to run live TrueID connector smoke tests.",
)
class TrueIdApiIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.api = TrueIdApi(
            session=requests.Session(),
            host=os.environ["TRUEID_TEST_URL"],
            api_key=os.environ["TRUEID_TEST_API_KEY"],
        )

    def test_live_mappings_endpoint(self):
        data = self.api.get_active_mappings()

        self.assertIsInstance(data, list)

    def test_live_events_endpoint(self):
        data = self.api.get_events_since(0)

        self.assertIsInstance(data, list)


if __name__ == "__main__":
    unittest.main()

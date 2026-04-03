import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SYNC_DIR = REPO_ROOT / "integrations" / "sycope"

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(SYNC_DIR))

from sycope.exceptions import SycopeApiError
from trueid_sync import (
    merge_lookup_data,
    prepare_runtime_config,
    select_lookup_user,
    sync_lookup,
)


class FakeSycopeApi:
    def __init__(self, saved_lookup, indexes=None, lookup_id="lookup-123", index_error=None):
        self.saved_lookup = saved_lookup
        self.indexes = indexes if indexes is not None else []
        self.lookup_id = lookup_id
        self.index_error = index_error
        self.edits = []

    def get_lookup(self, lookup_name, lookup_type="csvFile"):
        return (self.lookup_id, self.saved_lookup)

    def edit_lookup(self, lookup_id, updated_lookup, lookup_type="csvFile"):
        self.edits.append(
            {
                "lookup_id": lookup_id,
                "updated_lookup": updated_lookup,
                "lookup_type": lookup_type,
            }
        )

    def get_user_indicies(self):
        if self.index_error is not None:
            raise self.index_error
        return self.indexes


class TrueIdSyncTests(unittest.TestCase):
    def test_select_lookup_user_prefers_interactive_identity(self):
        mapping = {
            "current_users": ["ANONYMOUS", "jan.test", "DC01$"],
            "user": "jan.test@LAB.TRUEID.LOCAL",
        }

        self.assertEqual(select_lookup_user(mapping), "jan.test")

    def test_select_lookup_user_uses_fallback_user_when_current_users_missing(self):
        mapping = {"current_users": [], "user": "jan.test@LAB.TRUEID.LOCAL"}

        self.assertEqual(select_lookup_user(mapping), "jan.test@LAB.TRUEID.LOCAL")

    def test_select_lookup_user_handles_none_current_users(self):
        mapping = {"current_users": None, "user": "jan.test@LAB.TRUEID.LOCAL"}

        self.assertEqual(select_lookup_user(mapping), "jan.test@LAB.TRUEID.LOCAL")

    def test_select_lookup_user_handles_blank_current_user(self):
        mapping = {"current_users": [""], "user": "jan.test"}

        self.assertEqual(select_lookup_user(mapping), "jan.test")

    def test_select_lookup_user_handles_missing_current_users_key(self):
        mapping = {"user": "jan.test"}

        self.assertEqual(select_lookup_user(mapping), "jan.test")

    def test_select_lookup_user_keeps_upn_suffix_when_it_is_best_identity(self):
        mapping = {"current_users": ["ANONYMOUS", "jan.test@LAB.TRUEID.LOCAL"]}

        self.assertEqual(select_lookup_user(mapping), "jan.test@LAB.TRUEID.LOCAL")

    def test_select_lookup_user_falls_back_to_machine_account_when_needed(self):
        mapping = {"current_users": ["ANONYMOUS", "DC01$"]}

        self.assertEqual(select_lookup_user(mapping), "DC01$")

    def test_merge_lookup_data_preserves_existing_rows_and_uses_selected_user(self):
        saved_lookup = {
            "file": {
                "columns": ["ip", "mac", "user", "hostname", "vendor", "last_seen"],
                "rows": [
                    ["192.0.2.10", "", "manual-entry", "", "", ""],
                    ["10.50.0.100", "old-mac", "ANONYMOUS", "", "", "old-ts"],
                ],
            }
        }
        trueid_mappings = [
            {
                "ip": "10.50.0.100",
                "mac": "00:11:22:33:44:55",
                "current_users": ["ANONYMOUS", "jan.test", "DC01$"],
                "vendor": "Dell",
                "last_seen": 1712148627,
            }
        ]

        updated_lookup, summary = merge_lookup_data(saved_lookup, trueid_mappings, {})
        rows_by_ip = {row[0]: row for row in updated_lookup["file"]["rows"]}

        self.assertEqual(summary, {"added": 0, "modified": 1, "unchanged": 0})
        self.assertEqual(rows_by_ip["192.0.2.10"][2], "manual-entry")
        self.assertEqual(
            rows_by_ip["10.50.0.100"],
            ["10.50.0.100", "00:11:22:33:44:55", "jan.test", "", "Dell", "1712148627"],
        )

    def test_sync_lookup_updates_lookup_with_selected_user(self):
        saved_lookup = {
            "file": {
                "columns": ["ip", "mac", "user", "hostname", "vendor", "last_seen"],
                "rows": [],
            }
        }
        sycope = FakeSycopeApi(saved_lookup)
        trueid_mappings = [
            {
                "ip": "10.50.0.100",
                "mac": "00:11:22:33:44:55",
                "current_users": ["ANONYMOUS", "jan.test"],
                "vendor": "Dell",
                "last_seen": 1712148627,
            }
        ]

        sync_lookup(sycope, trueid_mappings, {"lookup_name": "TrueID_Enrichment"})

        self.assertEqual(len(sycope.edits), 1)
        rows = sycope.edits[0]["updated_lookup"]["file"]["rows"]
        self.assertEqual(
            rows,
            [["10.50.0.100", "00:11:22:33:44:55", "jan.test", "", "Dell", "1712148627"]],
        )

    def test_merge_lookup_data_skips_ipv6_rows(self):
        updated_lookup, summary = merge_lookup_data(
            {"file": {"columns": ["ip", "mac", "user", "hostname", "vendor", "last_seen"], "rows": []}},
            [{"ip": "2001:db8::10", "current_users": ["jan.test"]}],
            {},
        )

        self.assertEqual(updated_lookup["file"]["rows"], [])
        self.assertEqual(summary, {"added": 0, "modified": 0, "unchanged": 0})

    def test_prepare_runtime_config_keeps_pattern_b_when_index_exists(self):
        sycope = FakeSycopeApi(
            saved_lookup={"file": {"rows": []}},
            indexes=[{"config": {"name": "trueid_events"}}],
        )

        runtime_cfg = prepare_runtime_config(
            sycope,
            {
                "lookup_name": "TrueID_Enrichment",
                "enable_event_index": True,
                "index_name": "trueid_events",
            },
        )

        self.assertTrue(runtime_cfg["enable_event_index"])

    def test_prepare_runtime_config_disables_pattern_b_when_index_missing(self):
        sycope = FakeSycopeApi(saved_lookup={"file": {"rows": []}}, indexes=[])

        runtime_cfg = prepare_runtime_config(
            sycope,
            {
                "lookup_name": "TrueID_Enrichment",
                "enable_event_index": True,
                "index_name": "trueid_events",
            },
        )

        self.assertFalse(runtime_cfg["enable_event_index"])

    def test_prepare_runtime_config_disables_pattern_b_when_index_api_fails(self):
        sycope = FakeSycopeApi(
            saved_lookup={"file": {"rows": []}},
            index_error=SycopeApiError("custom index API unsupported"),
        )

        runtime_cfg = prepare_runtime_config(
            sycope,
            {
                "lookup_name": "TrueID_Enrichment",
                "enable_event_index": True,
                "index_name": "trueid_events",
            },
        )

        self.assertFalse(runtime_cfg["enable_event_index"])

    def test_prepare_runtime_config_leaves_lookup_only_mode_unchanged(self):
        sycope = FakeSycopeApi(saved_lookup={"file": {"rows": []}}, indexes=[])

        runtime_cfg = prepare_runtime_config(
            sycope,
            {
                "lookup_name": "TrueID_Enrichment",
                "enable_event_index": False,
                "index_name": "trueid_events",
            },
        )

        self.assertFalse(runtime_cfg["enable_event_index"])


if __name__ == "__main__":
    unittest.main()

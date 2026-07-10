#!/usr/bin/env python3
"""Regression tests for the raw ZAP report policy."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check-zap-report.py")
SPEC = importlib.util.spec_from_file_location("check_zap_report", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


def instance(uri: str, evidence: str = "", param: str = "") -> dict[str, str]:
    return {
        "uri": uri,
        "method": "GET",
        "param": param,
        "evidence": evidence,
    }


def report(alerts: list[dict[str, object]]) -> dict[str, object]:
    return {"site": [{"@name": POLICY.TARGET_URL, "alerts": alerts}]}


class ZapReportPolicyTests(unittest.TestCase):
    def test_accepts_reviewed_cache_observations(self) -> None:
        alerts = [
            {
                "pluginid": "10049",
                "alertRef": "10049-1",
                "riskcode": "0",
                "instances": [
                    instance(f"{POLICY.TARGET_URL}/metrics", "401"),
                ],
            },
            {
                "pluginid": "10049",
                "alertRef": "10049-3",
                "riskcode": "0",
                "instances": [
                    instance(POLICY.TARGET_URL),
                    instance(f"{POLICY.TARGET_URL}/js/api.js"),
                    instance(f"{POLICY.TARGET_URL}/css/index.css"),
                    instance(f"{POLICY.TARGET_URL}/robots.txt"),
                    instance(f"{POLICY.TARGET_URL}/sitemap.xml"),
                ],
            },
        ]
        _, errors = POLICY.validate_report(report(alerts))
        self.assertEqual(errors, [])

    def test_rejects_empty_or_malformed_report(self) -> None:
        _, errors = POLICY.validate_report({})
        self.assertTrue(errors)

    def test_accepts_valid_report_with_no_alerts(self) -> None:
        _, errors = POLICY.validate_report(report([]))
        self.assertEqual(errors, [])

    def test_rejects_unreviewed_cache_path(self) -> None:
        alert = {
            "pluginid": "10049",
            "alertRef": "10049-3",
            "riskcode": "0",
            "instances": [instance(f"{POLICY.TARGET_URL}/api/v1/users")],
        }
        _, errors = POLICY.validate_report(report([alert]))
        self.assertTrue(any("unreviewed cacheable" in error for error in errors))

    def test_rejects_every_non_cache_alert(self) -> None:
        alert = {
            "pluginid": "10055",
            "alertRef": "10055-5",
            "riskcode": "2",
            "instances": [instance(POLICY.TARGET_URL)],
        }
        _, errors = POLICY.validate_report(report([alert]))
        self.assertIn("unexpected ZAP alert 10055-5 (rule 10055)", errors)


if __name__ == "__main__":
    unittest.main()

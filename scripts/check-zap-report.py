#!/usr/bin/env python3
"""Reject every raw ZAP finding except narrowly reviewed cache observations."""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


TARGET_URL = "http://127.0.0.1:3000"


def instance_key(instance: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(instance.get("uri", "")),
        str(instance.get("method", "")).upper(),
        str(instance.get("param", "")),
        str(instance.get("evidence", "")),
    )


def validate_cache_alert(alert: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    alert_ref = str(alert.get("alertRef"))
    if str(alert.get("riskcode")) != "0":
        errors.append(f"reviewed cache alert {alert_ref} changed risk")
        return errors
    instances = alert.get("instances")
    if not isinstance(instances, list) or not instances:
        return [f"reviewed cache alert {alert_ref} has no instances"]

    for instance in instances:
        uri, method, param, evidence = instance_key(instance)
        parsed = urlparse(uri)
        path = parsed.path or "/"
        if (
            parsed.scheme != "http"
            or parsed.netloc != "127.0.0.1:3000"
            or parsed.query
            or parsed.fragment
            or ".." in path
            or method != "GET"
            or param
        ):
            errors.append(f"unreviewed cache instance: {(uri, method, param, evidence)!r}")
            continue

        if alert_ref == "10049-1":
            if path != "/metrics" or evidence != "401":
                errors.append(
                    f"unreviewed non-storable instance: {(uri, method, param, evidence)!r}"
                )
        elif alert_ref == "10049-3":
            is_public_asset = path in {"/", "/robots.txt", "/sitemap.xml"} or bool(
                re.fullmatch(r"/(?:css|js)/[A-Za-z0-9._/-]+\.(?:css|js)", path)
            )
            if not is_public_asset or evidence:
                errors.append(
                    f"unreviewed cacheable instance: {(uri, method, param, evidence)!r}"
                )
        else:
            errors.append(f"unexpected cache alert ref {alert_ref}")
    return errors


def validate_report(report: dict[str, Any]) -> tuple[Counter[str], list[str]]:
    accepted: Counter[str] = Counter()
    sites = report.get("site")
    if not isinstance(sites, list) or len(sites) != 1:
        return accepted, ["ZAP report must contain exactly one scanned site"]
    if sites[0].get("@name") != TARGET_URL:
        return accepted, ["ZAP report target does not match the CI target"]

    alerts = sites[0].get("alerts")
    if not isinstance(alerts, list):
        return accepted, ["ZAP report does not contain an alerts list"]

    errors: list[str] = []
    for alert in alerts:
        plugin_id = str(alert.get("pluginid", ""))
        alert_ref = str(alert.get("alertRef") or plugin_id)
        if plugin_id == "10049":
            errors.extend(validate_cache_alert(alert))
            accepted[alert_ref] += 1
        else:
            errors.append(f"unexpected ZAP alert {alert_ref} (rule {plugin_id})")
    return accepted, errors


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} <zap-report.json>", file=sys.stderr)
        return 2

    with Path(sys.argv[1]).open(encoding="utf-8-sig") as report_file:
        report = json.load(report_file)

    accepted, errors = validate_report(report)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    summary = ", ".join(f"{key}={value}" for key, value in sorted(accepted.items()))
    print(f"ZAP raw report is clean: {summary or 'no alerts'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

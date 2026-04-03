#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Create TrueID events Custom Index in Sycope.

Run this once before enabling Pattern B (event history injection).
Creates a Custom Index with the required field schema.
"""

import os
import sys

import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

EVENT_INDEX_FIELDS = [
    {"name": "timestamp", "type": "LONG"},
    {"name": "event_type", "type": "STRING"},
    {"name": "ip", "type": "IP"},
    {"name": "mac", "type": "STRING"},
    {"name": "user", "type": "STRING"},
    {"name": "hostname", "type": "STRING"},
    {"name": "vendor", "type": "STRING"},
    {"name": "details", "type": "STRING"},
]


def main() -> None:
    """Create the TrueID events Custom Index in Sycope."""
    suppress_ssl_warnings()
    setup_logging("trueid_install.log")

    cfg = load_config(
        CONFIG_FILE,
        required_fields=["sycope_host", "sycope_login", "sycope_pass"],
    )
    index_name = cfg.get("index_name", "trueid_events")

    with requests.Session() as session:
        session.headers.update({"Content-Type": "application/json"})
        api = SycopeApi(
            session,
            cfg["sycope_host"],
            cfg["sycope_login"],
            cfg["sycope_pass"],
            cfg.get("api_base", "/npm/api/v1/"),
        )
        try:
            existing = [
                item
                for item in api.get_user_indicies()
                if item.get("config", {}).get("name") == index_name
            ]
            if existing:
                print(f'Custom index "{index_name}" already exists.')
                return

            api.create_index(
                stream_name=index_name,
                fields=EVENT_INDEX_FIELDS,
                rotation="daily",
                active=True,
                store_raw=True,
            )
            print(f'Custom index "{index_name}" created successfully.')
        except SycopeError as exc:
            print(
                "Custom index setup is not available on this Sycope appliance or "
                f"for this account: {exc}\n"
                "Leave enable_event_index=false and continue with lookup-only mode.",
                file=sys.stderr,
            )
            sys.exit(1)
        finally:
            api.log_out()


if __name__ == "__main__":
    main()

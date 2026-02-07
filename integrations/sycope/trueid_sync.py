#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TrueID to Sycope Synchronization Script.

Synchronizes identity data (IP-to-user/MAC/device mappings) from TrueID
to a Sycope CSV Lookup for real-time NetFlow enrichment. Optionally injects
authentication events into a Sycope Custom Index for forensic analysis.

Architecture:
- Pattern A (Lookup): GET lookup → merge with TrueID data → PUT full replace
- Pattern B (Index):  Fetch events since last run → POST /index/inject

Based on the official phpIPAM→Sycope integration pattern from
SycopeSolutions/Integrations repository.

Script version: 1.0
Requires Sycope >= 3.1
"""

import logging
import os
import sys

import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from trueid_api import TrueIdApi
from sycope.api import SycopeApi
from sycope.config import load_config
from sycope.exceptions import SycopeError
from sycope.logging import setup_logging, suppress_ssl_warnings

logger = logging.getLogger(__name__)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

# Lookup column definition for TrueID enrichment.
CSV_COLUMNS = ["ip", "mac", "user", "hostname", "vendor", "last_seen"]

# Timestamp tracking file for event deduplication (Pattern B).
LAST_TIMESTAMP_FILE = os.path.join(SCRIPT_DIR, "last_event_timestamp.txt")


def build_trueid_conn(cfg: dict) -> TrueIdApi:
    """
    Create TrueIdApi instance from config.

    Parameters:
        cfg: Loaded config dict with trueid_host, trueid_api_base keys.

    Returns:
        Configured TrueIdApi client.
    """
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})

    return TrueIdApi(
        session=session,
        host=cfg["trueid_host"],
        api_base=cfg.get("trueid_api_base", "/api/v1"),
        api_key=cfg.get("trueid_api_key"),
    )


def setup_sycope_connection(cfg: dict) -> tuple:
    """
    Initialize Sycope API connection.

    Parameters:
        cfg: Loaded config dict with sycope_host, sycope_login, sycope_pass.

    Returns:
        Tuple of (SycopeApi, Session).
    """
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})

    sycope = SycopeApi(
        session=session,
        host=cfg["sycope_host"],
        login=cfg["sycope_login"],
        password=cfg["sycope_pass"],
        api_endpoint=cfg.get("api_base", "/npm/api/v1/"),
        api_endpoint_lookup="config-element-lookup/csvFile",
    )

    return sycope, session


def fetch_trueid_mappings(trueid: TrueIdApi) -> list:
    """
    Fetch active IP mappings from TrueID.

    Parameters:
        trueid: Initialized TrueIdApi client.

    Returns:
        List of mapping dicts or empty list on error.
    """
    try:
        mappings = trueid.get_active_mappings()
        logging.info(f"TrueID: Retrieved {len(mappings)} active mappings")
        return mappings
    except Exception as e:
        logging.error(f"TrueID: Failed to fetch mappings: {e}")
        return []


def merge_lookup_data(saved_lookup: dict, trueid_mappings: list, cfg: dict) -> tuple:
    """
    Merge TrueID data with existing Sycope lookup content.

    Follows phpipam_sync.py merge pattern:
    - Existing entries not in TrueID data are PRESERVED (manual entries safe)
    - TrueID entries overwrite existing entries with same IP key
    - New TrueID entries are added

    Parameters:
        saved_lookup: Current lookup state from Sycope GET.
        trueid_mappings: Fresh mapping list from TrueID API.
        cfg: Config dict (reserved for future options).

    Returns:
        Tuple of (updated_lookup_dict, summary_counts_dict).
    """
    columns = saved_lookup.get("file", {}).get("columns", CSV_COLUMNS)
    rows = saved_lookup.get("file", {}).get("rows", [])

    logger.debug(f"Merge: existing rows={len(rows)}, new mappings={len(trueid_mappings)}")

    # Build index by IP (column 0).
    existing = {}
    for row in rows:
        if row and len(row) > 0:
            existing[row[0]] = row

    summary = {"added": 0, "modified": 0, "unchanged": 0}

    for m in trueid_mappings:
        ip = m.get("ip")
        if not ip:
            continue

        # Skip IPv6 for now (Sycope Lookup may not handle it).
        if ":" in ip:
            logger.debug(f"Skipping IPv6 address: {ip}")
            continue

        # Extract user from current_users list.
        users = m.get("current_users", [])
        user = users[0] if users else m.get("user", "")

        # Format last_seen as ISO string or epoch ms.
        last_seen = m.get("last_seen", "")

        new_row = [
            str(ip),
            str(m.get("mac", "") or ""),
            str(user),
            "",  # hostname (not stored in TrueID mappings yet)
            str(m.get("vendor", "") or ""),
            str(last_seen),
        ]

        if ip in existing:
            if existing[ip] != new_row:
                existing[ip] = new_row
                summary["modified"] += 1
            else:
                summary["unchanged"] += 1
        else:
            existing[ip] = new_row
            summary["added"] += 1

    # Rebuild lookup structure.
    updated = dict(saved_lookup)
    if "file" not in updated:
        updated["file"] = {}
    updated["file"]["columns"] = CSV_COLUMNS
    updated["file"]["rows"] = list(existing.values())

    logger.debug(f"Merge result: {summary}, total rows: {len(updated['file']['rows'])}")

    return updated, summary


def sync_lookup(sycope: SycopeApi, trueid_data: list, cfg: dict) -> None:
    """
    Pattern A: Sync TrueID mappings to Sycope CSV Lookup.

    Flow: GET current lookup → merge with TrueID data → PUT full replacement.

    Parameters:
        sycope: Authenticated SycopeApi instance.
        trueid_data: List of active mapping dicts from TrueID.
        cfg: Config dict with lookup_name key.
    """
    lookup_name = cfg["lookup_name"]

    logger.debug(f"Getting existing lookup: {lookup_name}")
    lookup_id, saved_lookup = sycope.get_lookup(lookup_name, lookup_type="csvFile")

    if lookup_id == "0":
        logging.warning(
            f'Lookup "{lookup_name}" not found in Sycope. '
            f"Please create it manually in Sycope UI: "
            f"Configuration → Mapping → Lookups → Add CSV File lookup "
            f"with columns: {CSV_COLUMNS}"
        )
        return

    logger.debug(f"Lookup ID: {lookup_id}")
    logger.debug(f"Existing rows: {len(saved_lookup.get('file', {}).get('rows', []))}")

    updated_lookup, summary = merge_lookup_data(saved_lookup, trueid_data, cfg)

    total_changes = summary["added"] + summary["modified"]

    if total_changes == 0:
        logging.info("No changes detected. Skipping update.")
        return

    logging.info(
        f"Changes: added={summary['added']}, "
        f"modified={summary['modified']}, "
        f"unchanged={summary['unchanged']}"
    )

    sycope.edit_lookup(lookup_id, updated_lookup, lookup_type="csvFile")
    logging.info(
        f'Lookup "{lookup_name}" updated with '
        f"{len(updated_lookup['file']['rows'])} total rows"
    )


def read_last_timestamp() -> int:
    """
    Read last processed event timestamp from tracking file.

    Returns:
        Unix timestamp (seconds) or 0 if no file exists.
    """
    try:
        with open(LAST_TIMESTAMP_FILE, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def write_last_timestamp(ts: int) -> None:
    """
    Save last processed event timestamp to tracking file.

    Parameters:
        ts: Unix timestamp (seconds) to persist.
    """
    with open(LAST_TIMESTAMP_FILE, "w") as f:
        f.write(str(ts))


def sync_events(sycope: SycopeApi, trueid: TrueIdApi, cfg: dict) -> None:
    """
    Pattern B: Inject TrueID auth events into Sycope Custom Index.

    Flow: Fetch events since last run → POST /index/inject (append-only).

    Parameters:
        sycope: Authenticated SycopeApi instance.
        trueid: TrueIdApi client.
        cfg: Config dict with index_name key.
    """
    index_name = cfg.get("index_name", "trueid_events")

    last_ts = read_last_timestamp()
    logger.debug(f"Fetching events since timestamp: {last_ts}")

    try:
        events = trueid.get_events_since(last_ts)
    except Exception as e:
        logging.error(f"Failed to fetch TrueID events: {e}")
        return

    if not events:
        logging.info("No new events to inject")
        return

    # Build rows for injection (array of arrays).
    columns = ["timestamp", "event_type", "ip", "mac", "user", "hostname", "vendor", "details"]
    rows = []
    max_ts = last_ts

    for event in events:
        ts_raw = event.get("timestamp", "")

        # The TrueID API returns ISO 8601 timestamps; convert to epoch ms.
        try:
            from datetime import datetime

            if isinstance(ts_raw, str):
                dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                ts_ms = int(dt.timestamp() * 1000)
                ts_epoch = int(dt.timestamp())
            elif isinstance(ts_raw, (int, float)):
                ts_epoch = int(ts_raw)
                ts_ms = int(ts_raw * 1000) if ts_raw < 1e12 else int(ts_raw)
            else:
                ts_ms = 0
                ts_epoch = 0
        except (ValueError, TypeError):
            ts_ms = 0
            ts_epoch = 0

        row = [
            ts_ms,
            str(event.get("source", "")),
            str(event.get("ip", "")),
            "",  # mac (not in events table)
            str(event.get("user", "")),
            "",  # hostname
            "",  # vendor
            str(event.get("raw_data", "")),
        ]
        rows.append(row)

        if ts_epoch > max_ts:
            max_ts = ts_epoch

    logging.info(f"Injecting {len(rows)} events into index '{index_name}'")

    try:
        sycope.inject_data(
            index_name=index_name,
            columns=columns,
            rows=rows,
            sort_timestamp=True,
        )
        logging.info(f"Successfully injected {len(rows)} events")
        write_last_timestamp(max_ts)
    except SycopeError as e:
        logging.error(f"Failed to inject events: {e}")


def main() -> None:
    """Main synchronization function — runs once per invocation."""
    # Load configuration.
    try:
        cfg = load_config(
            CONFIG_FILE,
            required_fields=[
                "trueid_host",
                "sycope_host",
                "sycope_login",
                "sycope_pass",
                "lookup_name",
            ],
        )
    except Exception as e:
        setup_logging("trueid_sync.log")
        logging.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Setup environment.
    suppress_ssl_warnings()
    setup_logging("trueid_sync.log", log_level=cfg.get("log_level", "info"))

    logger.debug("=" * 60)
    logger.debug("TrueID Sync script starting")
    logger.debug("=" * 60)

    logging.info("Starting TrueID → Sycope synchronization...")

    # Connect to TrueID.
    trueid = build_trueid_conn(cfg)

    # Connect to Sycope.
    sycope, sycope_session = setup_sycope_connection(cfg)

    try:
        # === Pattern A: Lookup Enrichment ===
        trueid_data = fetch_trueid_mappings(trueid)

        if trueid_data:
            sync_lookup(sycope, trueid_data, cfg)
        else:
            logging.warning("No TrueID data available. Skipping lookup sync.")

        # === Pattern B: Event History (optional) ===
        if cfg.get("enable_event_index", False):
            sync_events(sycope, trueid, cfg)

    except SycopeError as e:
        logging.error(f"Sycope API error: {e}")
        sys.exit(1)
    finally:
        logger.debug("Logging out from Sycope...")
        sycope.log_out()

    logger.debug("Script complete")


if __name__ == "__main__":
    main()

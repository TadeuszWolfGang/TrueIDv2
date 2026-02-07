"""
TrueID REST API wrapper.

Provides methods to fetch identity mappings and authentication events
from the TrueID web service (trueid-web, Rust/Axum).
"""

import logging
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class TrueIdApi:
    """
    TrueID REST API client.

    Attributes:
        host: TrueID web service URL (e.g., 'http://localhost:3000')
        session: requests.Session for HTTP connections
        api_base: Base API path (default: '/api/v1')
    """

    def __init__(
        self,
        session: requests.Session,
        host: str,
        api_base: str = "/api/v1",
        api_key: Optional[str] = None,
    ) -> None:
        """
        Initialize TrueID API client.

        Parameters:
            session: HTTP session for connection reuse.
            host: TrueID web service base URL.
            api_base: API path prefix.
            api_key: Optional Bearer token for authentication.
        """
        self.host = host.rstrip("/")
        self.session = session
        self.api_base = api_base
        self.api_key = api_key

        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})

        logger.debug(f"TrueIdApi initialized: host={self.host}, api_base={self.api_base}")

    def get_active_mappings(self) -> List[Dict[str, Any]]:
        """
        Fetch all currently active IP-to-identity mappings.

        Returns:
            List of mapping dicts with keys: ip, mac, current_users,
            last_seen, source, confidence_score, is_active, vendor.
        """
        url = f"{self.host}{self.api_base}/mappings"
        logger.debug(f"GET {url}")

        response = self.session.get(url, timeout=30)
        response.raise_for_status()

        data = response.json()
        logger.info(f"TrueID: Retrieved {len(data)} active mappings")
        if data:
            logger.debug(f"Sample mapping: {data[0]}")

        return data

    def get_events_since(self, since_timestamp: int) -> List[Dict[str, Any]]:
        """
        Fetch authentication/mapping change events since a given timestamp.

        Parameters:
            since_timestamp: Unix timestamp (seconds) — fetch events after this time.

        Returns:
            List of event dicts with keys: id, ip, user, source, timestamp, raw_data.
        """
        url = f"{self.host}{self.api_base}/events"
        params = {"since": since_timestamp}
        logger.debug(f"GET {url} params={params}")

        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()

        data = response.json()
        logger.info(f"TrueID: Retrieved {len(data)} events since {since_timestamp}")

        return data

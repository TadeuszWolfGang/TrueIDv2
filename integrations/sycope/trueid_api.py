"""
TrueID REST API wrapper.

Provides methods to fetch identity mappings and authentication events
from the TrueID web service (trueid-web, Rust/Axum).

Transport rules enforced here:

- Remote endpoints require HTTPS; plain HTTP is permitted only for exact
  loopback targets (the literal host ``localhost``, case-insensitive, or a
  loopback IP literal accepted by stdlib ``ipaddress``, including bracketed
  IPv6). DNS is never resolved, so aliases, subdomains, trailing-dot
  variants and abbreviated/legacy IPv4 spellings never enable HTTP.
- The assembled request URL is validated before every send, including after
  public fields (``host``/``api_base``) are mutated by a caller.
- Redirects are never followed: both GETs are sent with
  ``allow_redirects=False`` and every 300-399 status is rejected before
  JSON decoding.
- Embedded URL credentials are rejected before any credential header is
  assigned. Validation errors never echo the URL, headers or payload.
- Logs contain the operation, the HTTP status and safe exception type
  names only — never URLs, Location headers, reasons, exception text,
  API keys or payload samples.
"""

import ipaddress
import logging
import re
import unicodedata
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import idna
import requests

logger = logging.getLogger(__name__)

# Generic validation message. Deliberately excludes the offending URL and
# any credential, header or payload content that could leak through it.
_TRANSPORT_ERROR = (
    "TrueID requires a safe transport URL: HTTPS for remote hosts, HTTP "
    "only for loopback, without embedded credentials, unsafe characters or "
    "a malformed host or port"
)

_REDIRECT_ERROR = "TrueID request was redirected (HTTP {status}); redirects are not allowed"


def _is_loopback_host(hostname: str) -> bool:
    """
    Return True only for exact ``localhost`` or a loopback IP literal.

    The hostname is never resolved: subdomains, aliases and trailing-dot
    variants of ``localhost`` do not match, and abbreviated/legacy IPv4
    spellings are rejected by ``ipaddress`` itself.
    """
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _has_explicit_empty_port(netloc: str) -> bool:
    """Return True when the netloc ends with a bare ``:`` (empty port)."""
    # Strip userinfo first so credentials cannot mask a trailing colon.
    _, _, hostinfo = netloc.rpartition("@")
    return hostinfo.endswith(":")


def _validate_transport_url(url: str) -> tuple:
    """
    Validate a TrueID transport URL; raise ValueError when it is unsafe.

    The check runs before every send (and before credential headers are
    assigned) and rejects:

    - missing or non-string URLs;
    - whitespace and control characters, checked before parsing because
      ``urlsplit`` silently strips tabs and newlines;
    - backslashes, which different parsers treat as path separators;
    - unsupported or missing schemes;
    - missing or malformed hosts (including percent-encoded hosts);
    - embedded userinfo (``user``/``password``), which could redirect the
      request to an attacker-controlled host;
    - malformed, out-of-range, zero and explicitly empty ports. Omitted
      ports keep the normal HTTP(S) defaults;
    - plain HTTP to anything except exact ``localhost`` (case-insensitive)
      or a loopback IP literal accepted by stdlib ``ipaddress``.

    The raised ValueError never contains the URL or its credentials.
    """
    if not isinstance(url, str) or not url:
        raise ValueError(_TRANSPORT_ERROR)
    for character in url:
        if character.isspace() or unicodedata.category(character) == "Cc":
            raise ValueError(_TRANSPORT_ERROR)
    if "\\" in url:
        raise ValueError(_TRANSPORT_ERROR)
    try:
        parsed = urlsplit(url)
        port = parsed.port  # Raises for malformed and out-of-range ports.
    except ValueError:
        raise ValueError(_TRANSPORT_ERROR) from None
    if parsed.scheme not in ("https", "http"):
        raise ValueError(_TRANSPORT_ERROR)
    hostname = parsed.hostname
    if not hostname or "%" in hostname:
        raise ValueError(_TRANSPORT_ERROR)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(_TRANSPORT_ERROR)
    if parsed.query or parsed.fragment or "?" in url or "#" in url:
        raise ValueError(_TRANSPORT_ERROR)
    if _has_explicit_empty_port(parsed.netloc):
        raise ValueError(_TRANSPORT_ERROR)
    if port == 0:
        raise ValueError(_TRANSPORT_ERROR)

    # urlsplit accepts suffixes after a closing IPv6 bracket, wildcards and
    # malformed DNS labels. Check the complete authority, not just hostname.
    if parsed.netloc.startswith("["):
        closing = parsed.netloc.find("]")
        suffix = parsed.netloc[closing + 1:]
        if suffix and not re.fullmatch(r":[0-9]+", suffix):
            raise ValueError(_TRANSPORT_ERROR)
        try:
            address = ipaddress.IPv6Address(hostname)
        except ValueError:
            raise ValueError(_TRANSPORT_ERROR) from None
        normalized_host = str(address)
    else:
        if "[" in parsed.netloc or "]" in parsed.netloc or ":" in hostname:
            raise ValueError(_TRANSPORT_ERROR)
        if ":" in parsed.netloc and not re.fullmatch(
            r"[0-9]+", parsed.netloc.rsplit(":", 1)[1]
        ):
            raise ValueError(_TRANSPORT_ERROR)
        try:
            normalized_host = idna.encode(hostname, uts46=True).decode("ascii").lower()
        except (idna.IDNAError, UnicodeError):
            raise ValueError(_TRANSPORT_ERROR) from None
        dns_name = normalized_host.rstrip(".")
        if len(dns_name) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in dns_name.split(".")
        ):
            raise ValueError(_TRANSPORT_ERROR)
        if normalized_host.endswith(".."):
            raise ValueError(_TRANSPORT_ERROR)

    if parsed.scheme == "http" and not _is_loopback_host(hostname):
        raise ValueError(_TRANSPORT_ERROR)
    return parsed.scheme, normalized_host, port or (443 if parsed.scheme == "https" else 80)


def _reject_redirects(response: requests.Response) -> None:
    """
    Reject every 300-399 status before JSON decoding.

    ``raise_for_status()`` alone does not reject redirects, so this check
    runs explicitly on every response. The exception carries the status
    code only — never the Location header or its reason phrase.
    """
    if 300 <= response.status_code < 400:
        raise ValueError(_REDIRECT_ERROR.format(status=response.status_code))


class TrueIdApi:
    """
    TrueID REST API client.

    Attributes:
        host: TrueID web service URL (e.g., 'https://localhost:3000')
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
            api_key: Optional TrueID API key sent via the X-API-Key header.

        Raises:
            ValueError: If the host or assembled API URLs are unsafe.
                Both endpoints are validated before any credential header
                is assigned, so rejected input never receives the API key.
        """
        if not isinstance(host, str):
            raise ValueError(_TRANSPORT_ERROR)
        self.host = host.rstrip("/")
        self.session = session
        self.api_base = api_base
        self.api_key = api_key

        # Validate before any credential header assignment.
        self._request_url("mappings")
        self._request_url("events")

        if api_key:
            self.session.headers.update({"X-API-Key": api_key})

        logger.debug("TrueIdApi initialized with a validated transport URL")

    def _request_url(self, endpoint: str) -> str:
        """Validate current public fields and preserve the host's origin."""
        origin = _validate_transport_url(self.host)
        if not isinstance(self.api_base, str) or (
            self.api_base and (
                not self.api_base.startswith("/") or self.api_base.startswith("//")
            )
        ):
            raise ValueError(_TRANSPORT_ERROR)
        url = f"{self.host}{self.api_base}/{endpoint}"
        if _validate_transport_url(url) != origin:
            raise ValueError(_TRANSPORT_ERROR)
        return url

    def get_active_mappings(self) -> List[Dict[str, Any]]:
        """
        Fetch all currently active IP-to-identity mappings.

        Returns:
            List of mapping dicts with keys: ip, mac, current_users,
            last_seen, source, confidence_score, is_active, vendor.

        Raises:
            ValueError: If the assembled request URL is unsafe or if the
                response is a redirect (300-399). Redirects are never
                followed and the rejection happens before JSON decoding.
            requests.HTTPError: On 4xx/5xx responses (unchanged contract).
        """
        url = self._request_url("mappings")
        logger.debug("TrueID: requesting active mappings")

        response = self.session.get(url, timeout=30, allow_redirects=False)
        _reject_redirects(response)
        logger.debug("TrueID: active mappings response status: %s", response.status_code)
        response.raise_for_status()

        payload = response.json()
        data = payload.get("data", payload) if isinstance(payload, dict) else payload
        logger.info(f"TrueID: Retrieved {len(data)} active mappings")

        return data

    def get_events_since(self, since_timestamp: int) -> List[Dict[str, Any]]:
        """
        Fetch authentication/mapping change events since a given timestamp.

        Parameters:
            since_timestamp: Unix timestamp (seconds) — fetch events after this time.

        Returns:
            List of event dicts with keys: id, ip, user, source, timestamp, raw_data.

        Raises:
            ValueError: If the assembled request URL is unsafe or if the
                response is a redirect (300-399). Redirects are never
                followed and the rejection happens before JSON decoding.
            requests.HTTPError: On 4xx/5xx responses (unchanged contract).
        """
        url = self._request_url("events")
        params = {"since": since_timestamp}
        logger.debug("TrueID: requesting events since the last timestamp")

        response = self.session.get(url, params=params, timeout=30, allow_redirects=False)
        _reject_redirects(response)
        logger.debug("TrueID: events response status: %s", response.status_code)
        response.raise_for_status()

        payload = response.json()
        data = payload.get("data", payload) if isinstance(payload, dict) else payload
        logger.info("TrueID: Retrieved %s events", len(data))

        return data

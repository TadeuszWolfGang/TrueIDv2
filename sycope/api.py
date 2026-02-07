"""
Sycope REST API wrapper.

This module provides a Python wrapper for the Sycope REST API,
handling authentication, session management, and common operations
for indexes and lookups.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

import requests

from .exceptions import SycopeApiError, SycopeAuthError

logger = logging.getLogger(__name__)


class SycopeApi:
    """
    Sycope REST API client.

    Provides methods to interact with Sycope's REST API for managing
    custom indexes, lookups, and related operations.

    Attributes:
        host: Sycope server URL
        session: requests.Session for HTTP connections
        api_endpoint: Base API path (default: /npm/api/v1/)

    Example:
        >>> with requests.Session() as session:
        ...     api = SycopeApi(session, "https://sycope.example.com", "admin", "password")
        ...     indexes = api.get_user_indicies()
        ...     api.log_out()
    """

    def __init__(
        self,
        session: requests.Session,
        host: str,
        login: str,
        password: str,
        api_endpoint: str = "/npm/api/v1/",
        api_endpoint_lookup: str = "config-element-lookup/csvFile",
    ) -> None:
        """
        Initialize Sycope API client and authenticate.

        Args:
            session: requests.Session object for HTTP connections
            host: Sycope server URL (e.g., 'https://sycope.example.com')
            login: Username for authentication
            password: Password for authentication
            api_endpoint: Base API path (default: '/npm/api/v1/')
            api_endpoint_lookup: Lookup API endpoint suffix

        Raises:
            SycopeAuthError: If authentication fails
        """
        self.host = host.rstrip("/")
        self.session = session
        self.api_endpoint = api_endpoint if api_endpoint.endswith("/") else f"{api_endpoint}/"
        self.api_endpoint_lookup = api_endpoint_lookup

        logger.debug(f"Initializing SycopeApi with host={self.host}")
        logger.debug(f"API endpoint: {self.api_endpoint}")
        logger.debug(f"Lookup endpoint: {self.api_endpoint_lookup}")
        logger.debug(f"Authenticating user: {login}")

        # Authenticate
        payload = {"username": login, "password": password}
        login_url = f"{self.host}/npm/api/v1/login"
        logger.debug(f"POST {login_url}")
        logger.debug(f"Request payload: username={login}, password=***")

        try:
            response = session.post(
                login_url,
                json=payload,
                verify=False,
            )
            logger.debug(f"Response status code: {response.status_code}")
            logger.debug(f"Response headers: {dict(response.headers)}")
            data = response.json()
            logger.debug(f"Response body: {data}")
        except requests.RequestException as e:
            logger.debug(f"Connection error: {e}")
            raise SycopeAuthError(f"Failed to connect to Sycope API: {e}")
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            logger.debug(f"Raw response text: {response.text[:500] if hasattr(response, 'text') else 'N/A'}")
            raise SycopeAuthError(f"Invalid response from Sycope API: {e}")

        if data.get("status") != 200:
            error_msg = data.get("message", "Unknown error")
            logger.debug(f"Login failed with status {data.get('status')}: {error_msg}")
            raise SycopeAuthError(f"Login failed: {error_msg}")

        logger.info("Login to Sycope API successful")
        logger.debug(f"Session cookies: {dict(session.cookies)}")

    def _make_request(
        self,
        method: str,
        url: str,
        json_payload: Optional[Dict[str, Any]] = None,
        operation_name: str = "API request",
    ) -> requests.Response:
        """
        Make an HTTP request with debug logging.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            url: Full URL for the request
            json_payload: Optional JSON payload for POST/PUT requests
            operation_name: Description of the operation for logging

        Returns:
            Response object
        """
        logger.debug(f"--- {operation_name} ---")
        logger.debug(f"{method} {url}")
        if json_payload:
            # Truncate large payloads for logging
            payload_str = str(json_payload)
            if len(payload_str) > 1000:
                logger.debug(f"Request payload (truncated): {payload_str[:1000]}...")
                logger.debug(f"Full payload size: {len(payload_str)} chars")
            else:
                logger.debug(f"Request payload: {json_payload}")

        if method == "GET":
            response = self.session.get(url, verify=False)
        elif method == "POST":
            response = self.session.post(url, json=json_payload, verify=False)
        elif method == "PUT":
            response = self.session.put(url, json=json_payload, verify=False)
        elif method == "DELETE":
            response = self.session.delete(url, verify=False)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        logger.debug(f"Response status code: {response.status_code}")
        logger.debug(f"Response headers: {dict(response.headers)}")

        # Log response body with truncation for large responses
        try:
            response_text = response.text
            if len(response_text) > 2000:
                logger.debug(f"Response body (truncated): {response_text[:2000]}...")
                logger.debug(f"Full response size: {len(response_text)} chars")
            else:
                logger.debug(f"Response body: {response_text}")
        except Exception as e:
            logger.debug(f"Could not log response body: {e}")

        return response

    def log_out(self) -> requests.Response:
        """
        Log out from the Sycope API.

        Returns:
            Response object from the logout request
        """
        url = f"{self.host}{self.api_endpoint}logout"
        response = self._make_request("GET", url, operation_name="Logout")
        logger.info("Logged out from Sycope API")
        return response

    def get_user_indicies(self) -> List[Dict[str, Any]]:
        """
        Get all custom indexes.

        Returns:
            List of custom index dictionaries

        Raises:
            SycopeApiError: If the API request fails
        """
        logger.info("Searching in existing custom indexes...")
        url = f'{self.host}{self.api_endpoint}config-elements?filter=category="userIndex.index"'
        response = self._make_request("GET", url, operation_name="Get user indexes")

        try:
            all_data = response.json().get("data", [])
            logger.debug(f"Found {len(all_data) if isinstance(all_data, list) else 0} custom indexes")
            if all_data and isinstance(all_data, list):
                for idx in all_data:
                    logger.debug(f"  Index: id={idx.get('id')}, name={idx.get('config', {}).get('name')}")
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when fetching indexes")

        return all_data if isinstance(all_data, list) else []

    def get_lookups(self) -> List[Dict[str, Any]]:
        """
        Get all saved lookups.

        Returns:
            List of lookup dictionaries

        Raises:
            SycopeApiError: If the API request fails
        """
        logger.info("Getting all saved Lookups...")
        url = f'{self.host}{self.api_endpoint}config-elements?offset=0&limit=2147483647&filter=category = "lookup.lookup"'
        response = self._make_request("GET", url, operation_name="Get lookups")

        try:
            all_data = response.json().get("data", [])
            logger.debug(f"Found {len(all_data) if isinstance(all_data, list) else 0} lookups")
            if all_data and isinstance(all_data, list):
                for lookup in all_data[:10]:  # Log first 10 to avoid spam
                    logger.debug(f"  Lookup: id={lookup.get('id')}, name={lookup.get('config', {}).get('name')}")
                if len(all_data) > 10:
                    logger.debug(f"  ... and {len(all_data) - 10} more lookups")
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when fetching lookups")

        return all_data if isinstance(all_data, list) else []

    def get_lookup(
        self,
        lookup_name: str,
        lookup_type: str = "csvFile",
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Get a specific lookup by name.

        Args:
            lookup_name: Name of the lookup to retrieve
            lookup_type: Type of lookup ('csvFile' or 'subnet')

        Returns:
            Tuple of (lookup_id, lookup_data). Returns ("0", {}) if not found.
        """
        logger.debug(f"Looking for lookup: name={lookup_name}, type={lookup_type}")
        all_data = self.get_lookups()
        matching = [x for x in all_data if x.get("config", {}).get("name") == lookup_name]

        logger.info(f'Searching for the Lookup "{lookup_name}" in saved Lookups...')
        logger.debug(f"Found {len(matching)} matching lookups")

        if not matching:
            logger.warning(f'Could not find lookup with the name "{lookup_name}"')
            return "0", {}

        lookup_id = matching[0]["id"]
        logger.debug(f"Found lookup ID: {lookup_id}")

        # Determine endpoint based on lookup type
        if lookup_type == "subnet":
            endpoint = "config-element-lookup/subnet"
        else:
            endpoint = self.api_endpoint_lookup
        logger.debug(f"Using endpoint: {endpoint}")

        url = f"{self.host}{self.api_endpoint}{endpoint}/{lookup_id}"
        response = self._make_request("GET", url, operation_name=f"Get lookup {lookup_name}")

        try:
            saved_lookup = response.json()
            logger.debug(f"Retrieved lookup data: keys={list(saved_lookup.keys()) if isinstance(saved_lookup, dict) else 'not a dict'}")
        except ValueError as e:
            logger.error(f"Invalid JSON response for lookup {lookup_id}: {e}")
            return "0", {}

        if isinstance(saved_lookup, dict):
            return str(lookup_id), saved_lookup

        logger.debug("Response was not a dictionary, returning empty result")
        return "0", {}

    def create_lookup(
        self,
        lookup_name: str,
        lookup: Dict[str, Any],
    ) -> str:
        """
        Create a new lookup.

        Args:
            lookup_name: Name for the new lookup
            lookup: Lookup configuration dictionary

        Returns:
            ID of the created lookup, or "0" if creation failed

        Raises:
            SycopeApiError: If the API request fails
        """
        logger.debug(f"Creating lookup: {lookup_name}")
        logger.debug(f"Lookup configuration keys: {list(lookup.keys())}")

        url = f"{self.host}{self.api_endpoint}{self.api_endpoint_lookup}"
        response = self._make_request("POST", url, json_payload=lookup, operation_name=f"Create lookup {lookup_name}")

        try:
            data = response.json()
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when creating lookup")

        if data.get("status") == 200:
            lookup_id = data.get("id", "0")
            logger.info(f'New Lookup "{lookup_name}" with ID "{lookup_id}" has been created')
            logger.debug(f"Create lookup response: {data}")
            return lookup_id

        error_msg = data.get("message", "Unknown error")
        logger.error(f"Failed to create lookup: {error_msg}")
        logger.debug(f"Error response: {data}")
        raise SycopeApiError(
            f"Failed to create lookup: {error_msg}",
            status_code=data.get("status"),
            response=data,
        )

    def edit_lookup(
        self,
        lookup_id: str,
        lookup: Dict[str, Any],
        lookup_type: str = "csvFile",
    ) -> None:
        """
        Update an existing lookup.

        Args:
            lookup_id: ID of the lookup to update
            lookup: Updated lookup configuration dictionary
            lookup_type: Type of lookup ('csvFile' or 'subnet')

        Raises:
            SycopeApiError: If the API request fails
        """
        logger.debug(f"Editing lookup: id={lookup_id}, type={lookup_type}")
        logger.debug(f"Updated lookup configuration keys: {list(lookup.keys())}")

        # Determine endpoint based on lookup type
        if lookup_type == "subnet":
            endpoint = "config-element-lookup/subnet"
        else:
            endpoint = self.api_endpoint_lookup
        logger.debug(f"Using endpoint: {endpoint}")

        url = f"{self.host}{self.api_endpoint}{endpoint}/{lookup_id}"
        response = self._make_request("PUT", url, json_payload=lookup, operation_name=f"Edit lookup {lookup_id}")

        try:
            data = response.json()
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when editing lookup")

        if data.get("status") == 200:
            logger.info(f'Data in the Lookup ID "{lookup_id}" has been successfully modified')
            logger.debug(f"Edit lookup response: {data}")
            return

        error_msg = data.get("message", "Unknown error")
        logger.error(f"Failed to edit lookup: {error_msg}")
        logger.debug(f"Error response: {data}")
        raise SycopeApiError(
            f"Failed to edit lookup: {error_msg}",
            status_code=data.get("status"),
            response=data,
        )

    def privacy_check_lookup(self, lookup_id: str) -> str:
        """
        Check privacy configuration for a lookup.

        Args:
            lookup_id: ID of the lookup to check

        Returns:
            Privacy setting: "Public", "Private", or empty string if unknown
        """
        logger.info("Checking privacy configuration...")
        logger.debug(f"Checking privacy for lookup ID: {lookup_id}")

        url = f"{self.host}{self.api_endpoint}permissions/CONFIGURATION.lookup.lookup/{lookup_id}"

        try:
            response = self._make_request("GET", url, operation_name=f"Check privacy for lookup {lookup_id}")
            data = response.json()
            logger.debug(f"Privacy response: {data}")
        except Exception as e:
            logger.error(f"Could not get privacy configuration: {e}")
            logger.debug(f"Exception details: {type(e).__name__}: {e}")
            return ""

        if not data or data.get("objectId") != lookup_id:
            logger.error("Invalid privacy response")
            logger.debug(f"Expected objectId={lookup_id}, got objectId={data.get('objectId') if data else 'None'}")
            return ""

        saved_perms = data.get("sidPerms", [])
        logger.debug(f"Saved permissions: {saved_perms}")

        # Definition for Public Privacy
        public_perms = [{"sid": "ROLE_USER", "perms": ["VIEW"]}]
        # Definition for Private Privacy
        private_perms: List[Dict[str, Any]] = []

        if saved_perms == public_perms:
            logger.debug("Privacy identified as: Public")
            return "Public"
        elif saved_perms == private_perms:
            logger.debug("Privacy identified as: Private")
            return "Private"
        else:
            logger.warning(
                f'Could not identify privacy configuration for Lookup ID "{lookup_id}". '
                "Custom Shared Privacy may be in use."
            )
            logger.debug(f"Unknown permission configuration: {saved_perms}")
            return ""

    def privacy_edit_lookup(
        self,
        lookup_id: str,
        lookup_privacy: str,
    ) -> None:
        """
        Change privacy setting for a lookup.

        Args:
            lookup_id: ID of the lookup to modify
            lookup_privacy: Target privacy setting ("Public" or "Private")

        Raises:
            SycopeApiError: If the privacy change fails
            ValueError: If an unsupported privacy option is specified
        """
        logger.debug(f"Changing privacy for lookup {lookup_id} to {lookup_privacy}")

        current_privacy = self.privacy_check_lookup(lookup_id)
        logger.debug(f"Current privacy: {current_privacy}")

        if current_privacy == lookup_privacy:
            logger.info(
                f'Privacy in Lookup ID "{lookup_id}" is already "{lookup_privacy}". No changes required.'
            )
            return

        public_perms = [{"sid": "ROLE_USER", "perms": ["VIEW"]}]
        private_perms: List[Dict[str, Any]] = []

        if lookup_privacy == "Public":
            target_perms = public_perms
        elif lookup_privacy == "Private":
            target_perms = private_perms
        else:
            logger.debug(f"Invalid privacy option: {lookup_privacy}")
            raise ValueError(f"Unsupported privacy option: {lookup_privacy}. Use 'Public' or 'Private'.")

        logger.debug(f"Target permissions: {target_perms}")

        url = f"{self.host}{self.api_endpoint}permissions/CONFIGURATION.lookup.lookup/{lookup_id}"
        response = self._make_request("PUT", url, json_payload=target_perms, operation_name=f"Edit privacy for lookup {lookup_id}")

        try:
            data = response.json()
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when editing privacy")

        if data.get("sidPerms") == target_perms:
            logger.info(f'Privacy for Lookup ID "{lookup_id}" has been changed to "{lookup_privacy}"')
            return

        logger.error(f"Failed to change privacy for lookup {lookup_id}")
        logger.debug(f"Expected sidPerms={target_perms}, got {data.get('sidPerms')}")
        raise SycopeApiError(
            f"Failed to change privacy to {lookup_privacy}",
            response=data,
        )

    def create_index(
        self,
        stream_name: str,
        fields: List[Dict[str, Any]],
        rotation: str,
        active: bool = True,
        store_raw: bool = True,
    ) -> None:
        """
        Create a new custom index.

        Args:
            stream_name: Name for the new index
            fields: List of field definitions
            rotation: Rotation policy (e.g., "daily", "weekly")
            active: Whether the index is active (default: True)
            store_raw: Whether to store raw data (default: True)

        Raises:
            SycopeApiError: If the index creation fails
        """
        logger.debug(f"Creating index: {stream_name}")
        logger.debug(f"Index parameters: rotation={rotation}, active={active}, store_raw={store_raw}")
        logger.debug(f"Number of fields: {len(fields)}")
        for i, field in enumerate(fields):
            logger.debug(f"  Field {i}: {field}")

        payload = {
            "name": stream_name,
            "active": active,
            "rotation": rotation,
            "storeRaw": store_raw,
            "fields": fields,
        }

        url = f"{self.host}{self.api_endpoint}config-element-index/user-index"
        response = self._make_request("POST", url, json_payload=payload, operation_name=f"Create index {stream_name}")

        try:
            data = response.json()
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when creating index")

        if data.get("status") == 200:
            logger.info(f'New custom index "{stream_name}" has been created')
            logger.debug(f"Create index response: {data}")
            return

        error_msg = data.get("message", "Unknown error")
        logger.error(f"Failed to create index: {error_msg}")
        logger.debug(f"Error response: {data}")
        raise SycopeApiError(
            f"Failed to create index: {error_msg}",
            status_code=data.get("status"),
            response=data,
        )

    def remove_index(self, index_name: str) -> None:
        """
        Remove a custom index by name.

        Args:
            index_name: Name of the index to remove

        Raises:
            SycopeApiError: If the index removal fails or index not found
        """
        logger.debug(f"Removing index: {index_name}")

        all_data = self.get_user_indicies()
        matching = [x for x in all_data if x.get("config", {}).get("name") == index_name]
        logger.debug(f"Found {len(matching)} indexes matching name '{index_name}'")

        if not matching:
            logger.debug(f"Index not found: {index_name}")
            raise SycopeApiError(f"Could not find an index with the name '{index_name}'")

        index_id = matching[0]["id"]
        logger.info(f'Found custom index "{index_name}" with ID "{index_id}"')
        logger.debug(f"Full index data: {matching[0]}")

        url = f"{self.host}{self.api_endpoint}config-element-index/user-index/{index_id}"
        response = self._make_request("DELETE", url, operation_name=f"Remove index {index_name}")

        try:
            data = response.json()
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when removing index")

        if data.get("status") == 200:
            logger.info(f'Custom index "{index_name}" has been successfully removed')
            logger.debug(f"Remove index response: {data}")
            return

        error_msg = data.get("message", "Unknown error")
        logger.error(f"Failed to remove index: {error_msg}")
        logger.debug(f"Error response: {data}")
        raise SycopeApiError(
            f"Failed to remove index '{index_name}': {error_msg}",
            status_code=data.get("status"),
            response=data,
        )

    def delete_lookup(
        self,
        lookup_name: str,
        lookup_type: str = "csvFile",
    ) -> None:
        """
        Delete a lookup by name.

        Args:
            lookup_name: Name of the lookup to delete
            lookup_type: Type of lookup ('csvFile' or 'subnet')

        Raises:
            SycopeApiError: If the lookup is not found or deletion fails
        """
        logger.debug(f"Deleting lookup: name={lookup_name}, type={lookup_type}")

        lookup_id, _ = self.get_lookup(lookup_name, lookup_type)

        if lookup_id == "0":
            logger.debug(f"Lookup not found: {lookup_name}")
            raise SycopeApiError(f"Lookup '{lookup_name}' not found")

        # Determine endpoint based on lookup type
        if lookup_type == "subnet":
            endpoint = "config-element-lookup/subnet"
        else:
            endpoint = self.api_endpoint_lookup
        logger.debug(f"Using endpoint: {endpoint}")

        logger.info(f'Deleting lookup "{lookup_name}" with ID "{lookup_id}"')

        url = f"{self.host}{self.api_endpoint}{endpoint}/{lookup_id}"
        response = self._make_request("DELETE", url, operation_name=f"Delete lookup {lookup_name}")

        try:
            data = response.json()
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when deleting lookup")

        if data.get("status") == 200:
            logger.info(f'Lookup "{lookup_name}" has been successfully deleted')
            logger.debug(f"Delete lookup response: {data}")
            return

        error_msg = data.get("message", "Unknown error")
        logger.error(f"Failed to delete lookup: {error_msg}")
        logger.debug(f"Error response: {data}")
        raise SycopeApiError(
            f"Failed to delete lookup '{lookup_name}': {error_msg}",
            status_code=data.get("status"),
            response=data,
        )

    def inject_data(
        self,
        index_name: str,
        columns: List[str],
        rows: List[List[Any]],
        sort_timestamp: bool = True,
    ) -> Dict[str, Any]:
        """
        Inject data rows into a custom index.

        Args:
            index_name: Name of the target index
            columns: List of column names matching the index schema
            rows: List of data rows (each row is a list of values)
            sort_timestamp: Whether to sort by timestamp (default: True)

        Returns:
            API response dictionary

        Raises:
            SycopeApiError: If the injection fails

        Example:
            >>> api.inject_data(
            ...     "my_index",
            ...     ["timestamp", "ip", "value"],
            ...     [[1234567890000, "192.168.1.1", 42.5], [1234567891000, "192.168.1.2", 37.2]]
            ... )
        """
        logger.debug(f"Injecting data into index: {index_name}")
        logger.debug(f"Columns: {columns}")
        logger.debug(f"Number of rows: {len(rows)}")
        logger.debug(f"Sort timestamp: {sort_timestamp}")

        if rows:
            logger.debug(f"First row sample: {rows[0]}")
            if len(rows) > 1:
                logger.debug(f"Last row sample: {rows[-1]}")

        if not rows:
            logger.info("No data to inject (empty rows)")
            logger.debug("Returning early due to empty rows")
            return {"status": 200, "message": "No data to inject"}

        payload = {
            "columns": columns,
            "indexName": index_name,
            "sortTimestamp": sort_timestamp,
            "rows": rows,
        }

        logger.info(f"Injecting {len(rows)} rows into index '{index_name}'")

        url = f"{self.host}{self.api_endpoint}index/inject"
        response = self._make_request("POST", url, json_payload=payload, operation_name=f"Inject data into {index_name}")

        try:
            data = response.json()
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when injecting data")

        if data.get("status") == 200:
            logger.info(f"Successfully injected {len(rows)} rows into '{index_name}'")
            logger.debug(f"Inject data response: {data}")
            return data

        error_msg = data.get("message", "Unknown error")
        logger.error(f"Failed to inject data: {error_msg}")
        logger.debug(f"Error response: {data}")
        raise SycopeApiError(
            f"Failed to inject data into '{index_name}': {error_msg}",
            status_code=data.get("status"),
            response=data,
        )

    def run_query(
        self,
        nql: str,
        start_time: str,
        end_time: str,
        limit: int = 50000,
        wait_time: int = 30000,
        fs_active: bool = False,
    ) -> Dict[str, Any]:
        """
        Run an NQL pipeline query.

        Args:
            nql: NQL query string (e.g., 'src stream="my_index"')
            start_time: Start time in ISO format with @ prefix (e.g., '@2024-01-01T00:00:00+00:00')
            end_time: End time in ISO format with @ prefix
            limit: Maximum number of results per page (default: 50000)
            wait_time: Query timeout in milliseconds (default: 30000)
            fs_active: Whether to use full-text search (default: False)

        Returns:
            Dictionary containing 'jobId' and 'data' with query metadata

        Raises:
            SycopeApiError: If the query fails

        Example:
            >>> result = api.run_query(
            ...     'src stream="my_index" | where ip == "192.168.1.1"',
            ...     '@2024-01-01T00:00:00+00:00',
            ...     '@2024-01-02T00:00:00+00:00'
            ... )
            >>> job_id = result['jobId']
            >>> total = result['data']['total']
        """
        logger.debug(f"Running NQL query")
        logger.debug(f"NQL: {nql}")
        logger.debug(f"Time range: {start_time} to {end_time}")
        logger.debug(f"Query parameters: limit={limit}, wait_time={wait_time}, fs_active={fs_active}")

        payload = {
            "startTime": start_time,
            "endTime": end_time,
            "nql": nql,
            "fsActive": fs_active,
            "waitTime": wait_time,
            "limit": limit,
        }

        logger.info(f"Running NQL query: {nql[:100]}...")

        url = f"{self.host}{self.api_endpoint}pipeline/run"
        response = self._make_request("POST", url, json_payload=payload, operation_name="Run NQL query")

        try:
            data = response.json()
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when running query")

        if "jobId" not in data:
            error_msg = data.get("message", "Unknown error - no jobId in response")
            logger.error(f"Query failed: {error_msg}")
            logger.debug(f"Error response: {data}")
            raise SycopeApiError(
                f"Query failed: {error_msg}",
                response=data,
            )

        job_id = data["jobId"]
        total = data.get("data", {}).get("total", "unknown")
        columns = data.get("data", {}).get("columns", [])

        logger.info(f"Query started, jobId: {job_id}, total results: {total}")
        logger.debug(f"Query job ID: {job_id}")
        logger.debug(f"Total results: {total}")
        logger.debug(f"Result columns: {columns}")
        logger.debug(f"Full query response keys: {list(data.keys())}")

        return data

    def get_query_results(
        self,
        job_id: str,
        limit: int = 50000,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Fetch results from a completed query job.

        Args:
            job_id: Job ID returned from run_query()
            limit: Maximum number of results to fetch (default: 50000)
            offset: Number of results to skip (default: 0)

        Returns:
            Dictionary containing 'data' list with query results

        Raises:
            SycopeApiError: If fetching results fails

        Example:
            >>> # Fetch all results with pagination
            >>> query_result = api.run_query(nql, start, end)
            >>> total = query_result['data']['total']
            >>> all_data = []
            >>> for offset in range(0, total, 50000):
            ...     page = api.get_query_results(query_result['jobId'], limit=50000, offset=offset)
            ...     all_data.extend(page['data'])
        """
        logger.debug(f"Fetching query results: jobId={job_id}, offset={offset}, limit={limit}")

        payload = {
            "limit": limit,
            "offset": offset,
        }

        url = f"{self.host}{self.api_endpoint}pipeline/{job_id}/data"
        response = self._make_request("POST", url, json_payload=payload, operation_name=f"Get query results for job {job_id}")

        try:
            data = response.json()
        except ValueError as e:
            logger.debug(f"JSON decode error: {e}")
            raise SycopeApiError("Invalid JSON response when fetching query results")

        if "data" not in data:
            error_msg = data.get("message", "Unknown error - no data in response")
            logger.error(f"Failed to fetch results: {error_msg}")
            logger.debug(f"Error response: {data}")
            raise SycopeApiError(
                f"Failed to fetch query results: {error_msg}",
                response=data,
            )

        result_count = len(data["data"]) if isinstance(data["data"], list) else 0
        logger.debug(f"Fetched {result_count} results")
        if result_count > 0:
            logger.debug(f"First result sample: {data['data'][0]}")

        return data

    def query_all_results(
        self,
        nql: str,
        start_time: str,
        end_time: str,
        page_size: int = 50000,
    ) -> List[Dict[str, Any]]:
        """
        Run a query and fetch all results with automatic pagination.

        This is a convenience method that combines run_query() and
        get_query_results() to fetch all matching data.

        Args:
            nql: NQL query string
            start_time: Start time in ISO format with @ prefix
            end_time: End time in ISO format with @ prefix
            page_size: Number of results per page (default: 50000)

        Returns:
            List of all result dictionaries

        Raises:
            SycopeApiError: If the query or result fetching fails

        Example:
            >>> results = api.query_all_results(
            ...     'src stream="my_index"',
            ...     '@2024-01-01T00:00:00+00:00',
            ...     '@2024-01-02T00:00:00+00:00'
            ... )
            >>> print(f"Found {len(results)} records")
        """
        logger.debug(f"query_all_results called")
        logger.debug(f"NQL: {nql}")
        logger.debug(f"Time range: {start_time} to {end_time}")
        logger.debug(f"Page size: {page_size}")

        # Run the query
        query_result = self.run_query(nql, start_time, end_time, limit=page_size)
        job_id = query_result["jobId"]
        total = query_result.get("data", {}).get("total", 0)

        logger.debug(f"Job ID: {job_id}")
        logger.debug(f"Total results to fetch: {total}")

        if total == 0:
            logger.info("Query returned no results")
            return []

        # Calculate number of pages
        num_pages = (total + page_size - 1) // page_size
        logger.debug(f"Will fetch {num_pages} page(s) of results")

        # Fetch all pages
        all_data = []
        for page_num, offset in enumerate(range(0, total, page_size), 1):
            logger.debug(f"Fetching page {page_num}/{num_pages} (offset={offset})")
            page = self.get_query_results(job_id, limit=page_size, offset=offset)
            page_data = page.get("data", [])
            all_data.extend(page_data)
            logger.debug(f"Page {page_num} returned {len(page_data)} results, total so far: {len(all_data)}")

        logger.info(f"Fetched {len(all_data)} total results")
        return all_data

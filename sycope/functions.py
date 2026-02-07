"""
Utility functions for Sycope integrations.

DEPRECATED: This module is maintained for backwards compatibility.
Use the following modules instead:
- sycope.config: load_config, validate_sycope_config
- sycope.logging: setup_logging, suppress_ssl_warnings
- sycope.exceptions: SycopeError, SycopeAuthError, SycopeApiError
"""

import warnings
from typing import Any, Dict

from .config import load_config as _load_config


def load_config(path: str) -> Dict[str, Any]:
    """
    Load configuration from JSON file.

    DEPRECATED: Use sycope.config.load_config() instead for more features
    including validation and list-to-set conversion.

    Args:
        path: Path to the config.json file

    Returns:
        Configuration dictionary with normalized values
    """
    warnings.warn(
        "sycope.functions.load_config is deprecated. "
        "Use sycope.config.load_config instead for additional features.",
        DeprecationWarning,
        stacklevel=2,
    )

    # Call the new implementation with backwards-compatible defaults
    # The old implementation converted specific Suricata fields to sets
    return _load_config(
        path,
        list_to_set_fields=[
            "anomaly_whitelist",
            "alert_whitelist",
            "anomaly_blacklist",
            "alert_blacklist",
        ],
    )

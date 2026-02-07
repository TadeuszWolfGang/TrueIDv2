"""
Configuration loading and validation utilities.

This module provides functions for loading JSON configuration files
and validating that required fields are present.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .exceptions import SycopeConfigError

logger = logging.getLogger(__name__)

# Required fields for Sycope API connection
SYCOPE_REQUIRED_FIELDS = ["sycope_host", "sycope_login", "sycope_pass"]


def load_config(
    path: str,
    required_fields: Optional[List[str]] = None,
    list_to_set_fields: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Load and validate configuration from a JSON file.

    This function loads a JSON configuration file, normalizes URL fields,
    validates required fields, and optionally converts list fields to sets
    for faster lookup operations.

    Args:
        path: Path to the config.json file
        required_fields: List of field names that must be present in config.
            If None, no validation is performed.
        list_to_set_fields: List of field names to convert from list to set.
            For each field, a new key with "_set" suffix is added.

    Returns:
        Configuration dictionary with normalized values

    Raises:
        FileNotFoundError: If the config file doesn't exist
        json.JSONDecodeError: If the config file contains invalid JSON
        SycopeConfigError: If required fields are missing

    Example:
        >>> cfg = load_config(
        ...     "config.json",
        ...     required_fields=["sycope_host", "index_name"],
        ...     list_to_set_fields=["alert_whitelist", "alert_blacklist"]
        ... )
        >>> cfg["sycope_host"]
        'https://sycope.example.com'
        >>> "alert_whitelist_set" in cfg
        True
    """
    logger.debug(f"Loading configuration from: {path}")
    logger.debug(f"Required fields: {required_fields}")
    logger.debug(f"List-to-set fields: {list_to_set_fields}")

    try:
        with open(path, "r", encoding="utf-8") as fp:
            cfg = json.load(fp)
        logger.debug(f"Successfully parsed JSON configuration")
        logger.debug(f"Configuration keys: {list(cfg.keys())}")
    except FileNotFoundError:
        logger.debug(f"Configuration file not found: {path}")
        raise FileNotFoundError(f"Configuration file not found: {path}")
    except json.JSONDecodeError as e:
        logger.debug(f"Invalid JSON in configuration file: {e}")
        raise SycopeConfigError(f"Invalid JSON in configuration file {path}: {e}")

    # Normalize Sycope host URL (strip whitespace and trailing slashes)
    if "sycope_host" in cfg:
        original_host = cfg["sycope_host"]
        cfg["sycope_host"] = cfg["sycope_host"].strip().rstrip("/")
        logger.debug(f"Normalized sycope_host: '{original_host}' -> '{cfg['sycope_host']}'")

    # Normalize API base path (ensure leading/trailing slashes)
    if "api_base" in cfg:
        original_api_base = cfg["api_base"]
        api_base = cfg["api_base"].strip().strip("/")
        cfg["api_base"] = f"/{api_base}/"
        logger.debug(f"Normalized api_base: '{original_api_base}' -> '{cfg['api_base']}'")

    # Validate required fields
    if required_fields:
        logger.debug(f"Validating required fields: {required_fields}")
        missing = [f for f in required_fields if f not in cfg]
        if missing:
            logger.debug(f"Missing required fields: {missing}")
            raise SycopeConfigError(
                f"Missing required configuration fields: {', '.join(missing)}"
            )
        logger.debug("All required fields present")

    # Convert list fields to sets for faster lookup
    if list_to_set_fields:
        logger.debug(f"Converting list fields to sets: {list_to_set_fields}")
        for key in list_to_set_fields:
            lst = cfg.get(key)
            set_key = f"{key}_set"
            if isinstance(lst, list):
                cfg[set_key] = set(lst)
                logger.debug(f"Converted {key} (list of {len(lst)} items) to {set_key}")
            else:
                cfg[set_key] = set()
                logger.debug(f"Created empty {set_key} (original {key} was not a list)")

    # Log configuration values (redact sensitive fields)
    logger.debug("Configuration values:")
    for key, value in cfg.items():
        if key in ("sycope_pass", "password", "token", "api_key", "secret"):
            logger.debug(f"  {key}: ***REDACTED***")
        elif isinstance(value, (list, set)):
            logger.debug(f"  {key}: [{len(value)} items]")
        elif isinstance(value, str) and len(value) > 100:
            logger.debug(f"  {key}: {value[:100]}...")
        else:
            logger.debug(f"  {key}: {value}")

    logger.info(f"Loaded configuration from {path}")
    return cfg


def validate_sycope_config(cfg: Dict[str, Any]) -> None:
    """
    Validate that Sycope connection fields are present in configuration.

    Args:
        cfg: Configuration dictionary to validate

    Raises:
        SycopeConfigError: If any required Sycope fields are missing
    """
    logger.debug(f"Validating Sycope configuration")
    logger.debug(f"Required Sycope fields: {SYCOPE_REQUIRED_FIELDS}")

    missing = [f for f in SYCOPE_REQUIRED_FIELDS if f not in cfg]
    if missing:
        logger.debug(f"Missing Sycope configuration fields: {missing}")
        raise SycopeConfigError(
            f"Missing required Sycope configuration fields: {', '.join(missing)}"
        )

    logger.debug("Sycope configuration validation passed")
    logger.debug(f"  sycope_host: {cfg.get('sycope_host')}")
    logger.debug(f"  sycope_login: {cfg.get('sycope_login')}")
    logger.debug(f"  sycope_pass: ***REDACTED***")


def get_config_value(
    cfg: Dict[str, Any],
    key: str,
    default: Any = None,
    required: bool = False,
) -> Any:
    """
    Get a configuration value with optional default and validation.

    Args:
        cfg: Configuration dictionary
        key: Key to retrieve
        default: Default value if key is not present
        required: If True, raise SycopeConfigError when key is missing

    Returns:
        Configuration value or default

    Raises:
        SycopeConfigError: If required=True and key is missing
    """
    logger.debug(f"Getting config value: key={key}, required={required}, default={default}")

    if key in cfg:
        value = cfg[key]
        # Redact sensitive values in debug output
        if key in ("sycope_pass", "password", "token", "api_key", "secret"):
            logger.debug(f"Found {key}: ***REDACTED***")
        else:
            logger.debug(f"Found {key}: {value}")
        return value

    if required:
        logger.debug(f"Required configuration key missing: {key}")
        raise SycopeConfigError(f"Required configuration key missing: {key}")

    logger.debug(f"Key {key} not found, using default: {default}")
    return default

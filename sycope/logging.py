"""
Logging configuration utilities.

This module provides functions for setting up consistent logging
across all integration scripts.
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from typing import Optional

# Debug format includes more details: filename, line number, function name
DEBUG_FORMAT = "%(asctime)s %(levelname)s [%(filename)s:%(lineno)d %(funcName)s] %(message)s"
STANDARD_FORMAT = "%(asctime)s %(levelname)s %(message)s"

# Valid log level names (case-insensitive)
VALID_LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


# Default rotating file handler settings
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_BACKUP_COUNT = 5  # Keep 5 backup files


def setup_logging(
    log_file: Optional[str] = None,
    level: Optional[int] = None,
    format_string: Optional[str] = None,
    debug: Optional[bool] = None,
    log_level: Optional[str] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> logging.Logger:
    """
    Configure logging to file and/or console.

    Sets up the root logger with consistent formatting across all
    integration scripts. Can output to both a file and stdout.
    File logging uses RotatingFileHandler to prevent log files from
    growing indefinitely.

    This function configures the root logger as a side effect. All child
    loggers (created via logging.getLogger(__name__)) automatically inherit
    the root logger's configuration. The return value is optional to use.

    Debug mode can be enabled by:
    - Setting debug=True parameter
    - Setting level=logging.DEBUG parameter
    - Setting log_level="debug" parameter
    - Setting SYCOPE_DEBUG=1 environment variable

    Args:
        log_file: Optional path to log file. If None, logs only to console.
        level: Logging level as int (e.g., logging.DEBUG). If None, determined
            by debug mode or log_level parameter.
        format_string: Log message format string. If None, uses appropriate default.
        debug: If True, enables debug mode with verbose format.
        log_level: Log level as string from config (e.g., "debug", "info").
            This is the recommended way to set log level from config.json.
            Valid values: "debug", "info", "warning", "error", "critical".
        max_bytes: Maximum size of log file before rotation (default: 10 MB).
        backup_count: Number of backup files to keep (default: 5).

    Returns:
        Configured root logger. Optional to capture - the configuration is
        applied globally to all loggers via the root logger.

    Example:
        >>> # Basic usage - configure root logger, use module-level logger
        >>> logger = logging.getLogger(__name__)
        >>> setup_logging("integration.log")  # return value optional
        >>> logger.info("Script started")

        >>> # Enable debug via log_level (from config.json)
        >>> setup_logging("integration.log", log_level=cfg.get("log_level", "info"))
        >>> logger.debug("Detailed debug info")

        >>> # Enable debug via parameter
        >>> setup_logging("integration.log", debug=True)
    """
    # Parse log_level string if provided
    parsed_level = None
    if log_level is not None:
        log_level_lower = log_level.lower().strip()
        if log_level_lower in VALID_LOG_LEVELS:
            parsed_level = VALID_LOG_LEVELS[log_level_lower]
        else:
            # Invalid log level - will be logged after setup
            pass

    # Determine if debug mode is enabled
    debug_mode = (
        debug is True
        or level == logging.DEBUG
        or parsed_level == logging.DEBUG
        or os.environ.get("SYCOPE_DEBUG", "").lower() in ("1", "true", "yes")
    )

    # Set level: explicit level > parsed log_level > debug mode default
    if level is not None:
        final_level = level
    elif parsed_level is not None:
        final_level = parsed_level
    elif debug_mode:
        final_level = logging.DEBUG
    else:
        final_level = logging.INFO

    # Set format based on debug mode
    if format_string is None:
        format_string = DEBUG_FORMAT if debug_mode else STANDARD_FORMAT

    handlers = [logging.StreamHandler(sys.stdout)]

    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        handlers.append(file_handler)

    # Clear any existing handlers on root logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    logging.basicConfig(
        level=final_level,
        format=format_string,
        handlers=handlers,
        force=True,  # Override any existing configuration
    )

    # Log invalid log_level after logging is configured
    if log_level is not None and log_level.lower().strip() not in VALID_LOG_LEVELS:
        logging.warning(
            f"Invalid log_level '{log_level}' in config. "
            f"Valid values: {', '.join(VALID_LOG_LEVELS.keys())}. Using default."
        )

    if debug_mode:
        logging.debug("Debug logging enabled")
        logging.debug(f"Log file: {log_file or 'None (console only)'}")
        logging.debug(f"Log level: {logging.getLevelName(final_level)}")

    return root_logger


def suppress_ssl_warnings() -> None:
    """
    Suppress urllib3 SSL certificate warnings.

    This is useful when connecting to Sycope instances with
    self-signed certificates. Call this once at the start of
    your script to avoid verbose SSL warnings in the output.

    Example:
        >>> suppress_ssl_warnings()
        >>> # SSL warnings are now suppressed for all requests
    """
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logging.debug("SSL certificate warnings suppressed")


def get_logger(name: str) -> logging.Logger:
    """
    Get a named logger instance.

    Use this to get a logger for a specific module or integration.

    Args:
        name: Logger name (typically __name__ of the calling module)

    Returns:
        Logger instance

    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("Processing started")
    """
    return logging.getLogger(name)

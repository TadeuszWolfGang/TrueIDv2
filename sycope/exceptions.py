"""
Custom exceptions for Sycope API operations.

This module defines a hierarchy of exceptions for handling errors
in Sycope API interactions.
"""

from typing import Any, Dict, Optional


class SycopeError(Exception):
    """
    Base exception for all Sycope-related errors.

    All custom exceptions in the sycope module inherit from this class,
    allowing callers to catch all Sycope errors with a single except clause.
    """

    pass


class SycopeAuthError(SycopeError):
    """
    Raised when authentication to the Sycope API fails.

    This includes invalid credentials, expired sessions, or
    network issues during the login process.
    """

    pass


class SycopeApiError(SycopeError):
    """
    Raised when a Sycope API operation fails.

    Attributes:
        message: Human-readable error description
        status_code: HTTP status code from the API response (if available)
        response: Full API response dictionary (if available)
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize SycopeApiError.

        Args:
            message: Human-readable error description
            status_code: HTTP status code from the API response
            response: Full API response dictionary for debugging
        """
        super().__init__(message)
        self.status_code = status_code
        self.response = response

    def __str__(self) -> str:
        """Return string representation with status code if available."""
        base_msg = super().__str__()
        if self.status_code:
            return f"{base_msg} (status: {self.status_code})"
        return base_msg


class SycopeConfigError(SycopeError):
    """
    Raised when configuration is invalid or missing required fields.

    This includes missing config files, invalid JSON, or
    missing required configuration keys.
    """

    pass

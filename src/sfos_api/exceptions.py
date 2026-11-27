"""Exception hierarchy and unified error helpers for sfos_api."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SFOSApiErrorInfo:
    """Unified, standardized representation of an SFOS API error.

    Captures error fields from both raised exceptions and API response bodies
    (such as batch operation error items).

    Attributes:
        message: Human-readable error message.
        error: Short error code or category string returned by the firewall.
        code: Numeric or string error code from the response payload.
        status_code: HTTP status code associated with the error.
        resource_id: Optional identifier or name of the affected resource.
        details: Raw error dictionary or response body for inspection.

    """

    message: str
    error: str | None = None
    code: str | int | None = None
    status_code: int | None = None
    resource_id: str | None = None
    details: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Convert error info to a clean dictionary representation."""
        result: dict[str, Any] = {
            "error": self.error,
            "message": self.message,
            "code": self.code,
            "status_code": self.status_code,
        }
        if self.resource_id is not None:
            result["resource_id"] = self.resource_id
        if self.details is not None:
            result["details"] = self.details
        return result

    def __str__(self) -> str:
        """Return a formatted string representation of the error."""
        parts: list[str] = []
        if self.status_code is not None:
            parts.append(f"[HTTP {self.status_code}]")
        if self.error:
            parts.append(f"{self.error}:")
        if self.resource_id:
            parts.append(f"(Resource: '{self.resource_id}')")
        parts.append(self.message)
        if self.code is not None and str(self.code) != str(self.status_code):
            parts.append(f"(code: {self.code})")
        return " ".join(parts)


class SFOSApiError(Exception):
    """Base exception for all SFOS API client errors.

    Attributes:
        message: Human-readable error description.
        status_code: HTTP status code (for example, 400, 404, 409, 500).
        error: Short error identifier from the firewall JSON body.
        code: Internal SFOS error code from the firewall JSON body.
        response_body: Decoded JSON response body or raw response text.

    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error: str | None = None,
        code: str | int | None = None,
        response_body: Any = None,
    ) -> None:
        """Initialize the SFOS API error with optional response metadata."""
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error = error
        self.code = code
        self.response_body = response_body

    @property
    def error_info(self) -> SFOSApiErrorInfo:
        """Return the standardized SFOSApiErrorInfo for this exception."""
        return parse_error(self)

    def __str__(self) -> str:
        """Return the string representation of the exception."""
        return self.message


class BadRequestError(SFOSApiError):
    """400: Bad request."""


class AuthenticationError(SFOSApiError):
    """401: Authentication required."""


class AuthorizationError(SFOSApiError):
    """403: Authorization required."""


class NotFoundError(SFOSApiError):
    """404: Not found."""


class ConflictError(SFOSApiError):
    """409: Conflict."""


class UnprocessableEntityError(SFOSApiError):
    """422: Unprocessable entity / validation error."""


class RateLimitError(SFOSApiError):
    """429: Too many requests / rate limit exceeded."""

    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        status_code: int | None = 429,
        error: str | None = None,
        code: str | int | None = None,
        response_body: Any = None,
    ) -> None:
        """Initialize RateLimitError with optional retry-after seconds."""
        super().__init__(message, status_code=status_code, error=error, code=code, response_body=response_body)
        self.retry_after = retry_after


class InternalServerError(SFOSApiError):
    """500: Internal server error."""


class UnexpectedError(InternalServerError):
    """500: Unexpected error."""


class BadGatewayError(InternalServerError):
    """502: Bad gateway."""


class ServiceUnavailableError(InternalServerError):
    """503: Service unavailable."""


class GatewayTimeoutError(InternalServerError):
    """504: Gateway timeout."""


class SFOSConnectionError(SFOSApiError):
    """Underlying HTTP transport or connection failure."""


class SFOSTimeoutError(SFOSApiError):
    """Request timed out while connecting, reading, or writing."""


def _parse_batch_item_error(entry: dict[str, Any]) -> SFOSApiErrorInfo:
    """Extract an SFOSApiErrorInfo from a single batch result item ({"item": ..., "error": ...})."""
    item_ref = entry.get("item")
    res_id: str | None = None
    if isinstance(item_ref, dict):
        raw_id = item_ref.get("id") or item_ref.get("name")
        if raw_id is not None:
            res_id = str(raw_id)

    err_val = entry.get("error")
    if isinstance(err_val, dict):
        raw_error = err_val.get("error")
        error = str(raw_error) if raw_error is not None else None
        message = str(err_val.get("message") or error or "API error")
        code = err_val.get("code")
        status_code = err_val.get("status_code")
        if status_code is None and isinstance(code, int) and 100 <= code <= 599:
            status_code = code
        if res_id is None:
            fallback_id = err_val.get("id") or err_val.get("name")
            if fallback_id is not None:
                res_id = str(fallback_id)
        return SFOSApiErrorInfo(
            message=message,
            error=error,
            code=code,
            status_code=status_code,
            resource_id=res_id,
            details=entry,
        )

    error_str = str(err_val) if err_val is not None else "deleteFailed"
    message_str = str(entry.get("message") or err_val or "Operation failed")
    return SFOSApiErrorInfo(
        message=message_str,
        error=error_str,
        code=entry.get("code"),
        status_code=entry.get("status_code"),
        resource_id=res_id,
        details=entry,
    )


def _extract_batch_failed_items(items: list[Any]) -> list[dict[str, Any]]:
    """Filter batch result items down to entries that failed."""
    return [entry for entry in items if isinstance(entry, dict) and ("error" in entry or entry.get("deleted") is False)]


def parse_error(target: Any) -> SFOSApiErrorInfo:
    """Extract a standardized SFOSApiErrorInfo from an exception, dictionary, or response body.

    Handles:
        - SFOSApiError and other Exception instances
        - Single API error dictionaries (e.g. {"error": "badRequest", "message": "...", "code": 400})
        - OpenAPI / client.delete() batch responses containing per-item errors in "items"
        - Batch response dictionaries containing an "errors" list (extracts the first error)
        - Strings and other representations

    Args:
        target: An exception, error dictionary, batch response, or string.

    Returns:
        A standardized SFOSApiErrorInfo instance.

    """
    if target is None:
        return SFOSApiErrorInfo(message="Unknown error")

    if isinstance(target, SFOSApiError):
        res_id = None
        if isinstance(target.response_body, dict):
            res_id = target.response_body.get("id") or target.response_body.get("name")
        return SFOSApiErrorInfo(
            message=target.message,
            error=target.error,
            code=target.code,
            status_code=target.status_code,
            resource_id=res_id,
            details=target.response_body,
        )

    if isinstance(target, dict):
        # Batch response containing "errors": list
        if "errors" in target and isinstance(target["errors"], list):
            err_list = target["errors"]
            if err_list:
                return parse_error(err_list[0])
            return SFOSApiErrorInfo(message="No errors in response", details=target)

        # OpenAPI / client.delete() batch response containing "items": list
        if "items" in target and isinstance(target["items"], list):
            failed_items = _extract_batch_failed_items(target["items"])
            if failed_items:
                return _parse_batch_item_error(failed_items[0])
            return SFOSApiErrorInfo(message="No errors in response", details=target)

        # Single batch result item: {"item": {...}, "error": {...}} or {"item": {...}, "deleted": False}
        if (
            "item" in target
            and isinstance(target.get("item"), dict)
            and ("error" in target or target.get("deleted") is False)
        ):
            return _parse_batch_item_error(target)

        # Direct error dictionary
        raw_error = target.get("error")
        error = str(raw_error) if raw_error is not None else None
        message = str(target.get("message") or error or "API error")
        code = target.get("code")
        status_code = target.get("status_code")
        if status_code is None and isinstance(code, int) and 100 <= code <= 599:
            status_code = code
        res_id = target.get("id") or target.get("name")
        return SFOSApiErrorInfo(
            message=message,
            error=error,
            code=code,
            status_code=status_code,
            resource_id=res_id,
            details=target,
        )

    if isinstance(target, list):
        if target:
            return parse_error(target[0])
        return SFOSApiErrorInfo(message="Empty error list")

    if isinstance(target, Exception):
        return SFOSApiErrorInfo(
            message=str(target) or type(target).__name__,
            error=type(target).__name__,
            details=getattr(target, "args", None),
        )

    return SFOSApiErrorInfo(message=str(target))


def parse_errors(target: Any) -> list[SFOSApiErrorInfo]:
    """Extract all standardized SFOSApiErrorInfo instances from a batch response, list, or exception.

    Args:
        target: Batch response dictionary, list of error dicts/exceptions, or a single error.

    Returns:
        A list of SFOSApiErrorInfo instances. If no errors are found, the list will be empty.

    """
    if target is None:
        return []

    if isinstance(target, dict):
        if "errors" in target and isinstance(target["errors"], list):
            return [parse_error(item) for item in target["errors"]]
        if "items" in target and isinstance(target["items"], list):
            return [_parse_batch_item_error(entry) for entry in _extract_batch_failed_items(target["items"])]

    if isinstance(target, list):
        return [parse_error(item) for item in target]

    return [parse_error(target)]


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "BadGatewayError",
    "BadRequestError",
    "ConflictError",
    "GatewayTimeoutError",
    "InternalServerError",
    "NotFoundError",
    "RateLimitError",
    "SFOSApiError",
    "SFOSApiErrorInfo",
    "SFOSConnectionError",
    "SFOSTimeoutError",
    "ServiceUnavailableError",
    "UnexpectedError",
    "UnprocessableEntityError",
    "parse_error",
    "parse_errors",
]

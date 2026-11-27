"""Lightweight SFOS API client implementation.

A zero-overhead, Python 3.11+ client that uses StrEnum domain classes for endpoints
and eliminates the Endpoint dataclass and monolithic Endpoints registry.
"""

from __future__ import annotations

import configparser
import contextlib
import logging
import re
import ssl
from collections.abc import Mapping, Sequence
from os import PathLike
from pathlib import Path
from types import TracebackType
from typing import IO, Any, Final, Self
from urllib.parse import quote

import httpx

from ._spec_metadata import (
    COLLECTION_QUERY_PARAMS,
    CURSOR_PAGINATED_ENDPOINTS,
    DELETE_BATCH_LIMITS,
    ENDPOINT_DELETE_FILTERS,
    NON_PAGINATED_COLLECTION_ENDPOINTS,
    SINGLE_DELETE_ONLY_ENDPOINTS,
)
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    BadGatewayError,
    BadRequestError,
    ConflictError,
    GatewayTimeoutError,
    InternalServerError,
    NotFoundError,
    RateLimitError,
    ServiceUnavailableError,
    SFOSApiError,
    SFOSConnectionError,
    SFOSTimeoutError,
    UnprocessableEntityError,
)
from .types import MovePayload

# Module-level logger for audit trail and debugging
logger = logging.getLogger(__name__)

DEFAULT_PORT: Final[int] = 4444
DEFAULT_VERIFY_SSL: Final[bool] = False
DEFAULT_TIMEOUT: Final[float] = 30.0
DEFAULT_PAGE_SIZE: Final[int] = 100


def _parse_verify_ssl(value: str) -> bool | str:
    """Parse INI verify_ssl value as bool or CA bundle file path."""
    cleaned = value.strip()
    if not cleaned:
        return DEFAULT_VERIFY_SSL
    lowered = cleaned.lower()
    if lowered in {"true", "1", "yes"}:
        return True
    if lowered in {"false", "0", "no"}:
        return False
    return cleaned


# Matches OpenAPI path template placeholders such as {idOrName}, {id}, {name}, {floodAttackType}
_PLACEHOLDER_RE: Final[re.Pattern[str]] = re.compile(r"\{([^}/]+)\}")

# Query filters accepted by filter-mode delete(). Anything else is rejected to prevent a
# mistyped filter from being ignored server-side and matching (then deleting) every item.
ALLOWED_DELETE_FILTERS: Final[frozenset[str]] = frozenset({"nameContains", "nameNotEquals"})

_UPLOAD_CONTENT_TYPES: Final[dict[str, str]] = {
    ".csv": "text/csv",
    ".txt": "text/plain",
}

# Bulk deletion constants (Sophos REST API defaults to max 50 items per /delete request,
# with endpoint-specific OpenAPI maxItems overrides imported from _spec_metadata).
DELETE_BATCH_SIZE: Final[int] = 50
DELETE_MAX_MATCHES: Final[int | None] = None


class SFOSClient:
    """Synchronous HTTPS client for the Sophos Firewall OS (SFOS) Configuration REST API.

    Provides native HTTP method operations (get, post, patch, delete), convenience
    wrappers (upload, move, test_connection), OpenAPI-aware auto-pagination, and
    context manager support for automatic session cleanup.
    """

    DELETE_BATCH_SIZE: int = DELETE_BATCH_SIZE
    DELETE_MAX_MATCHES: int | None = DELETE_MAX_MATCHES
    DELETE_BATCH_LIMITS: Mapping[str, int] = DELETE_BATCH_LIMITS

    def __init__(
        self,
        host: str | None = None,
        api_key: str | None = None,
        *,
        config_path: str | PathLike[str] | None = None,
        profile: str = "firewall",
        port: int | None = None,
        verify_ssl: bool | str | ssl.SSLContext | None = None,
        timeout: float | httpx.Timeout | None = None,
        transport: httpx.BaseTransport | None = None,
        strict_query_validation: bool = False,
    ) -> None:
        """Initialize the SFOS client with explicit settings or an INI profile.

        Args:
            host: Firewall IPv4/IPv6 address or hostname without protocol scheme.
            api_key: Bearer token generated in SFOS WebAdmin (Administration > API).
            config_path: Optional path to an INI configuration file.
            profile: INI section name to load when `config_path` is provided (default: "firewall").
            port: WebAdmin HTTPS port (default: 4444).
            verify_ssl: TLS certificate verification flag, CA bundle path, or ssl.SSLContext (default: False).
            timeout: Request timeout in seconds or an httpx.Timeout instance (default: 30.0).
            transport: Optional custom httpx.BaseTransport (for example, httpx.MockTransport).
            strict_query_validation: Validate collection read query parameters against OpenAPI.

        Raises:
            FileNotFoundError: If `config_path` is provided and does not exist.
            ValueError: If `profile` is missing, required credentials are missing/empty,
                or `host` includes a protocol scheme.

        """
        if config_path is not None:
            resolved_path = Path(config_path).expanduser()
            if not resolved_path.is_file():
                raise FileNotFoundError(f"Config file not found: {config_path}")
            parser = configparser.ConfigParser()
            parser.read(resolved_path, encoding="utf-8")
            if profile not in parser:
                raise ValueError(f"Profile '{profile}' not found in {config_path}")
            section = parser[profile]
            if host is None:
                host = section.get("host")
            if api_key is None:
                api_key = section.get("api_key")
            if port is None and section.get("port"):
                port = section.getint("port")
            if verify_ssl is None and section.get("verify_ssl") is not None:
                verify_ssl = _parse_verify_ssl(section["verify_ssl"])
            if timeout is None and section.get("timeout"):
                timeout = section.getfloat("timeout")

        if host is None:
            raise ValueError("host must be provided explicitly or via config file")
        if "://" in host:
            raise ValueError("Do not include a protocol in host; HTTPS is enforced.")
        clean_host = host.strip()
        if not clean_host:
            raise ValueError("host must not be empty")
        if api_key is None:
            raise ValueError("api_key must be provided explicitly or via config file")
        if not api_key:
            raise ValueError("api_key must not be empty")

        resolved_port = DEFAULT_PORT if port is None else port
        resolved_verify_ssl: bool | str | ssl.SSLContext = DEFAULT_VERIFY_SSL if verify_ssl is None else verify_ssl
        resolved_timeout: float | httpx.Timeout = DEFAULT_TIMEOUT if timeout is None else timeout

        self.strict_query_validation = strict_query_validation
        host_for_url = f"[{clean_host}]" if ":" in clean_host and not clean_host.startswith("[") else clean_host
        authority = f"{host_for_url}:{resolved_port}"
        self.base_url = f"https://{authority}/api/firewall-config/v1/"
        self.session = httpx.Client(
            base_url=self.base_url,
            headers={"Accept": "application/json", "Authorization": f"Bearer {api_key}"},
            timeout=resolved_timeout,
            verify=resolved_verify_ssl,
            transport=transport,
        )

    def __enter__(self) -> Self:
        """Enter the runtime context and return the client instance."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Exit the runtime context and close the HTTP session."""
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self.session.close()

    @staticmethod
    def _clean_params(params: Mapping[str, Any] | None) -> dict[str, Any] | None:
        """Remove None values from query parameters dictionary."""
        if params is None:
            return None
        clean = {k: v for k, v in params.items() if v is not None}
        return clean or None

    @classmethod
    def _resolve_path(cls, endpoint: str, id_or_name: str | None = None) -> str:
        """Resolve the full API path for a given endpoint and optional resource identifier.

        Any single path template placeholder (e.g. {idOrName}, {id}, {name},
        {floodAttackType}) is substituted with the URL-encoded id_or_name. Endpoints
        without a placeholder get /{id_or_name} appended.
        """
        placeholders = _PLACEHOLDER_RE.findall(endpoint)
        if len(placeholders) > 1:
            raise ValueError(
                f"Endpoint '{endpoint}' has multiple path parameters {placeholders}; only one is supported."
            )

        if id_or_name is None:
            if placeholders:
                raise ValueError(f"Endpoint '{endpoint}' requires 'id_or_name' (path parameter '{placeholders[0]}').")
            return endpoint

        quoted = quote(str(id_or_name), safe="")
        if placeholders:
            return _PLACEHOLDER_RE.sub(lambda _: quoted, endpoint, count=1)

        return f"{endpoint.rstrip('/')}/{quoted}"

    DEFAULT_ERROR_MESSAGES: Final[dict[int, str]] = {
        400: "Bad request.",
        401: "Authentication required.",
        403: "Authorization required.",
        404: "Not found.",
        409: "Conflict.",
        422: "Unprocessable entity.",
        429: "Too many requests / rate limit exceeded.",
        500: "Internal server error.",
        502: "Bad gateway.",
        503: "Service unavailable.",
        504: "Gateway timeout.",
    }

    ERROR_MAP: Final[dict[int, type[SFOSApiError]]] = {
        400: BadRequestError,
        401: AuthenticationError,
        403: AuthorizationError,
        404: NotFoundError,
        409: ConflictError,
        422: UnprocessableEntityError,
        429: RateLimitError,
        500: InternalServerError,
        502: BadGatewayError,
        503: ServiceUnavailableError,
        504: GatewayTimeoutError,
    }

    @classmethod
    def _error_details(cls, response: httpx.Response) -> tuple[str, str | None, str | int | None, Any]:
        """Extract error details from an HTTP response."""
        default_message = cls.DEFAULT_ERROR_MESSAGES.get(
            response.status_code, response.reason_phrase or "Unexpected error."
        )
        try:
            body = response.json()
        except ValueError:
            body = response.text
        if isinstance(body, dict):
            error = body.get("error")
            message = str(body.get("message") or error or default_message)
            code = body.get("code")
        else:
            error, code = None, None
            message = str(body or default_message)
        return message, error, code, body

    @classmethod
    def _raise_for_error(cls, response: httpx.Response) -> None:
        """Raise an appropriate exception based on the HTTP response status code."""
        if not response.is_error:
            return
        message, error, code, body = cls._error_details(response)
        exc_cls = cls.ERROR_MAP.get(
            response.status_code, InternalServerError if response.status_code >= 500 else SFOSApiError
        )
        if exc_cls is RateLimitError:
            retry_after_header = response.headers.get("retry-after")
            retry_after: float | None = None
            if retry_after_header:
                with contextlib.suppress(ValueError):
                    retry_after = float(retry_after_header)
            raise RateLimitError(
                message,
                retry_after=retry_after,
                status_code=response.status_code,
                error=error,
                code=code,
                response_body=body,
            )
        raise exc_cls(message, status_code=response.status_code, error=error, code=code, response_body=body)

    # =========================================================================
    # Low-Level Transport & Protocol Execution
    # =========================================================================

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Mapping[str, Any] | None = None,
        json_data: Any = None,
        data: Mapping[str, Any] | None = None,
        files: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """Send a raw HTTP request to the firewall API.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE).
            endpoint: Target API path relative to /api/firewall-config/v1/.
            params: Optional query string parameters (None values are stripped).
            json_data: Optional JSON-serializable request body.
            data: Optional form fields dictionary for multipart/form requests.
            files: Optional multipart files mapping/sequence forwarded to httpx.
            headers: Optional per-request HTTP headers.

        Returns:
            Decoded JSON response, plain text string, or None on 204 No Content.

        Raises:
            ValueError: If json_data is combined with files or data.
            SFOSTimeoutError: If the HTTP request times out.
            SFOSConnectionError: If a network or transport error occurs.
            SFOSApiError: If the firewall returns an HTTP 4xx or 5xx error response.

        """
        if json_data is not None and (files is not None or data is not None):
            raise ValueError("Cannot combine 'json_data' with multipart 'files' or form 'data'.")
        method = method.upper()
        clean_endpoint = endpoint.lstrip("/")
        logger.debug("%s %s", method, clean_endpoint)
        try:
            response = self.session.request(
                method,
                clean_endpoint,
                params=self._clean_params(params),
                json=json_data,
                data=dict(data) if data is not None else None,
                files=files,
                headers=headers,
            )
        except httpx.TimeoutException as err:
            raise SFOSTimeoutError(f"Request to '{clean_endpoint}' timed out: {err}") from err
        except (httpx.NetworkError, httpx.TransportError) as err:
            raise SFOSConnectionError(
                f"Connection failure communicating with firewall at '{clean_endpoint}': {err}"
            ) from err
        self._raise_for_error(response)
        if response.status_code == 204 or not response.content:
            return None
        if "json" in response.headers.get("content-type", "").lower():
            return response.json()
        return response.text

    # =========================================================================
    # Core CRUD Methods
    # =========================================================================

    def post(
        self,
        endpoint: str,
        data: Mapping[str, Any] | None = None,
        *,
        id_or_name: str | None = None,
        params: Mapping[str, Any] | None = None,
        files: Any = None,
        form_data: Mapping[str, Any] | None = None,
    ) -> Any:
        """Create a new resource, invoke an action, or upload multipart form data.

        Args:
            endpoint: API endpoint string or StrEnum domain member (e.g. Network.ZONES, SpoofProtection.TRUSTED_MACS_IMPORT).
            data: Optional dictionary containing JSON request payload data.
            id_or_name: Optional resource identifier for item-scoped actions or parameterized paths.
            params: Optional query parameters dictionary.
            files: Optional multipart files mapping/sequence forwarded to httpx.
            form_data: Optional form fields sent alongside files.

        Returns:
            Decoded response from the firewall (or None if 204 No Content).

        """
        if data is not None and (files is not None or form_data is not None):
            raise ValueError("Cannot combine JSON 'data' with multipart 'files' or 'form_data'.")
        path = self._resolve_path(endpoint, id_or_name)
        if files is not None or form_data is not None:
            return self.request("POST", path, params=params, data=form_data, files=files)
        return self.request("POST", path, params=params, json_data=dict(data) if data is not None else None)

    @staticmethod
    def _normalize_endpoint(endpoint: str) -> str:
        """Normalize an endpoint path to a leading-slash form without trailing slashes."""
        stripped = endpoint.strip("/")
        return f"/{stripped}" if stripped else "/"

    def _read_cursor_pages(self, endpoint: str, first: dict[str, Any], base_query: dict[str, Any]) -> dict[str, Any]:
        """Follow keyset/cursor pagination (fromKey / nextKey) until exhausted."""
        items = list(first["items"])
        first_pages = dict(first.get("pages") or {})
        pages = dict(first_pages)
        seen_keys: set[str] = set()
        next_key = pages.get("nextKey")

        while next_key:
            key_str = str(next_key)
            if key_str in seen_keys:
                break
            seen_keys.add(key_str)
            page = self.request("GET", endpoint, params={**base_query, "fromKey": key_str})
            if not isinstance(page, dict):
                break
            page_items = page.get("items")
            if isinstance(page_items, list):
                items.extend(page_items)
            next_pages = page.get("pages")
            if isinstance(next_pages, dict):
                pages = dict(next_pages)
                next_key = pages.get("nextKey")
            else:
                next_key = None

        result = dict(first)
        result["items"] = items
        merged_pages = {**first_pages, **pages, "size": len(items)}
        merged_pages["nextKey"] = next_key or None
        result["pages"] = merged_pages
        return result

    def _read_numbered_pages(self, endpoint: str, first: dict[str, Any], page_query: dict[str, Any]) -> dict[str, Any]:
        """Aggregate remaining numbered pages when total page count exceeds 1."""
        pages = first.get("pages")
        if not isinstance(pages, dict):
            return first

        total_pages = int(pages.get("total", 1))
        if total_pages <= 1:
            return first

        items = list(first["items"])
        for page_num in range(2, total_pages + 1):
            page = self.request("GET", endpoint, params={**page_query, "page": page_num})
            if isinstance(page, dict):
                page_items = page.get("items")
                if isinstance(page_items, list):
                    items.extend(page_items)

        result = dict(first)
        result["items"] = items
        result["pages"] = {
            "current": 1,
            "size": len(items),
            "maxSize": pages.get("maxSize", 100),
            "total": total_pages,
        }
        if "items" in pages:
            result["pages"]["items"] = pages["items"]
        return result

    def get(
        self,
        endpoint: str,
        id_or_name: str = "",
        params: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        """Read a single resource or a collection with OpenAPI-aware auto-pagination.

        Auto-pagination is enabled for collection reads when page, pageTotal, and
        fromKey are omitted. Both numbered pagination (page / pages.total) and
        cursor/keyset pagination (fromKey / pages.nextKey) are supported; non-paginated
        OpenAPI endpoints are queried once without injecting page/pageSize.

        Args:
            endpoint: API endpoint string or StrEnum domain member (e.g. Network.ZONES).
            id_or_name: Resource identifier or name for single resource read (default: empty string).
            params: Optional dictionary of query parameters.
            **kwargs: Optional query parameters as keyword arguments (merged with params).

        Returns:
            Single resource dictionary or combined results from all pages.

        """
        query = {**(params or {}), **kwargs}

        # Single resource or parameterized path
        if id_or_name:
            invalid = {"page", "pageSize", "pageTotal", "fromKey"} & query.keys()
            if invalid:
                raise ValueError(
                    f"Pagination parameters are not supported when reading a single resource: {sorted(invalid)}"
                )
            path = self._resolve_path(endpoint, id_or_name)
            return self.request("GET", path, params=query or None)

        # Collection
        base_path = endpoint
        if _PLACEHOLDER_RE.search(base_path):
            raise ValueError(
                f"Endpoint '{base_path}' contains path parameters that require 'id_or_name' to be specified."
            )

        norm_endpoint = self._normalize_endpoint(endpoint)
        if self.strict_query_validation and query:
            self._validate_read_query(norm_endpoint, query)

        # Explicit paging requested by caller
        explicit_paging = bool({"page", "pageTotal", "fromKey"} & query.keys())
        if explicit_paging:
            return self.request("GET", endpoint, params=query or None)

        if norm_endpoint in NON_PAGINATED_COLLECTION_ENDPOINTS or norm_endpoint in CURSOR_PAGINATED_ENDPOINTS:
            base_query = dict(query)
            first = self.request("GET", endpoint, params=base_query or None)
        else:
            page_size = max(1, min(int(query.get("pageSize", DEFAULT_PAGE_SIZE)), 100))
            base_query = {**query, "page": 1, "pageSize": page_size, "pageTotal": True}
            first = self.request("GET", endpoint, params=base_query)

        if not isinstance(first, dict) or not isinstance(first.get("items"), list):
            return first

        pages = first.get("pages")
        if isinstance(pages, dict) and pages.get("nextKey"):
            return self._read_cursor_pages(endpoint, first, query)
        return self._read_numbered_pages(endpoint, first, base_query)

    def patch(self, endpoint: str, id_or_name: str | None = None, *, data: Mapping[str, Any]) -> Any:
        """Update an existing resource or singleton setting using JSON Merge Patch (RFC 7396).

        Args:
            endpoint: API endpoint string or StrEnum domain member (e.g. Network.ADDRESSES_IPV4).
            id_or_name: Resource identifier or name (omit or pass None for singleton settings).
            data: Dictionary of resource attributes to merge-patch.

        Returns:
            Decoded response from the firewall (or None if 204 No Content).

        Raises:
            ValueError: If id_or_name is an empty string or required by a path template.

        """
        if id_or_name is not None:
            if not id_or_name:
                raise ValueError("id_or_name must not be empty")
            path = self._resolve_path(endpoint, id_or_name)
        else:
            path = self._resolve_path(endpoint)
        return self.request("PATCH", path, json_data=dict(data))

    @staticmethod
    def _validate_read_query(norm_endpoint: str, query: Mapping[str, Any]) -> None:
        """Validate GET collection query parameters against OpenAPI when strict mode is enabled."""
        if norm_endpoint not in COLLECTION_QUERY_PARAMS:
            return
        allowed = COLLECTION_QUERY_PARAMS[norm_endpoint]
        if norm_endpoint in CURSOR_PAGINATED_ENDPOINTS:
            allowed = allowed | {"fromKey"}
        unknown = query.keys() - allowed
        if unknown:
            raise ValueError(
                f"Unsupported query parameter(s) {sorted(unknown)} for '{norm_endpoint}'. Allowed: {sorted(allowed)}."
            )
        if "nameContains" in query and "nameNotEquals" in query:
            raise ValueError(
                "Sophos REST API does not allow 'nameContains' and 'nameNotEquals' together. Specify at most one name filter per request."
            )

    @staticmethod
    def _validate_delete_filters(norm_endpoint: str, filter_params: Mapping[str, Any]) -> None:
        """Validate query filters against the endpoint's OpenAPI delete-filter allowance."""
        allowed_filters = ENDPOINT_DELETE_FILTERS.get(norm_endpoint, ALLOWED_DELETE_FILTERS)
        if not allowed_filters:
            raise ValueError(
                f"Endpoint '{norm_endpoint}' does not support query-filter deletion; pass 'id_or_name' or 'items'."
            )
        unknown = filter_params.keys() - allowed_filters
        if unknown:
            raise ValueError(
                f"Unsupported delete filter(s) {sorted(unknown)}. Allowed filters: {sorted(allowed_filters)}."
            )
        if "nameContains" in filter_params and "nameNotEquals" in filter_params:
            raise ValueError(
                "Sophos REST API does not allow 'nameContains' and 'nameNotEquals' together. Specify at most one name filter per request."
            )

    def _delete_batches(self, delete_path: str, targets: list[dict[str, Any]], chunk_size: int) -> dict[str, Any]:
        """Execute POST .../delete in OpenAPI-bounded chunks and aggregate results."""
        aggregated_items: list[dict[str, Any]] = []
        total_errors = 0

        for i in range(0, len(targets), chunk_size):
            chunk = targets[i : i + chunk_size]
            try:
                api_resp = self.request("POST", delete_path, json_data={"items": chunk})
            except SFOSApiError as err:
                err_obj: dict[str, Any] = {
                    "error": err.error or type(err).__name__,
                    "message": str(err),
                }
                if err.code is not None:
                    err_obj["code"] = err.code
                aggregated_items.extend([{"item": t, "error": err_obj} for t in chunk])
                total_errors += len(chunk)
                continue

            if isinstance(api_resp, dict):
                chunk_items = api_resp.get("items")
                if isinstance(chunk_items, list):
                    aggregated_items.extend(chunk_items)
                else:
                    aggregated_items.extend([{"item": t, "deleted": True} for t in chunk])

                err_summary = api_resp.get("errors")
                reported_errors = 0
                if isinstance(err_summary, dict) and "total" in err_summary:
                    reported_errors = int(err_summary["total"])
                elif isinstance(err_summary, list):
                    reported_errors = len(err_summary)
                item_errors = sum(
                    1
                    for item in chunk_items or []
                    if isinstance(item, dict) and (item.get("deleted") is False or "error" in item)
                )
                total_errors += max(reported_errors, item_errors)
            else:
                aggregated_items.extend([{"item": t, "deleted": True} for t in chunk])

        return {"items": aggregated_items, "errors": {"total": total_errors}}

    def _delete_sequential(self, endpoint: str, targets: list[dict[str, Any]]) -> dict[str, Any]:
        """Execute sequential DELETE /{idOrName} calls for endpoints lacking POST .../delete."""
        aggregated_items: list[dict[str, Any]] = []
        total_errors = 0

        for target in targets:
            identifier = target.get("name") or target.get("id")
            if not identifier:
                raise ValueError(f"Cannot delete target without 'name' or 'id': {target!r}")
            path = self._resolve_path(endpoint, str(identifier))
            try:
                api_resp = self.request("DELETE", path)
            except SFOSApiError as err:
                err_obj: dict[str, Any] = {
                    "error": err.error or type(err).__name__,
                    "message": str(err),
                }
                if err.code is not None:
                    err_obj["code"] = err.code
                aggregated_items.append({"item": target, "error": err_obj})
                total_errors += 1
            else:
                deleted_flag = bool(api_resp.get("deleted", True)) if isinstance(api_resp, dict) else True
                aggregated_items.append({"item": target, "deleted": deleted_flag})
                if not deleted_flag:
                    total_errors += 1

        return {"items": aggregated_items, "errors": {"total": total_errors}}

    def delete(
        self,
        endpoint: str,
        id_or_name: str = "",
        params: Mapping[str, Any] | None = None,
        *,
        dry_run: bool = False,
        items: Sequence[str | Mapping[str, Any]] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Delete an existing resource by identifier, explicit batch, or filtered bulk deletion.

        Batch deletes chunk automatically to min(DELETE_BATCH_SIZE, spec_maxItems) where
        DELETE_BATCH_LIMITS supplies endpoint-specific OpenAPI maxItems overrides (default 50).
        Endpoints without a POST .../delete batch route fall back sequentially to DELETE /{idOrName}.

        Supported deletion modes:
          1. Single resource deletion via HTTP DELETE (id_or_name).
          2. Explicit batch deletion via items.
          3. Query-filter deletion via params or kwargs validated against endpoint-specific OpenAPI filters
             (e.g. nameContains/nameNotEquals, type for Network.SERVICES, name for
             Waf.PROTECTION_POLICIES, filter for IpsecVpn.SITE_TO_SITE_FAILOVER_GROUPS).

        Args:
            endpoint: API endpoint string or StrEnum domain member (e.g. Network.ADDRESSES_IPV4).
            id_or_name: Resource identifier or name for single resource deletion (default: empty string).
            params: Optional query filter parameters dictionary.
            dry_run: If True, resolve targets without sending any delete requests.
            items: Sequence of resource identifiers (strings) or item dictionaries for batch deletion.
            **kwargs: Optional query filter parameters validated per endpoint.

        Returns:
            A dictionary matching the standard Sophos batch delete API response:
            {"items": [{"item": {...}, "deleted": True}, ...], "errors": {"total": int}}.

        Raises:
            ValueError: If mutually exclusive modes, unsupported filters, or target limits are exceeded.

        """
        filter_params = {**(params or {}), **kwargs}

        has_id = bool(id_or_name)
        has_items = items is not None
        has_filters = bool(filter_params)

        # Enforce mutual exclusivity among the 3 modes
        selected_modes = int(has_id) + int(has_items) + int(has_filters)
        if selected_modes != 1:
            raise ValueError(
                "Provide exactly one deletion mode: single resource ('id_or_name'), explicit batch ('items'), or query filters ('params' / filter kwargs)."
            )

        norm_endpoint = self._normalize_endpoint(endpoint)
        base = endpoint.rstrip("/")
        delete_path = base if base.endswith("/delete") else f"{base}/delete"
        spec_limit = self.DELETE_BATCH_LIMITS.get(norm_endpoint, 50)
        chunk_size = max(1, min(self.DELETE_BATCH_SIZE, spec_limit))

        # Mode 1: Single Resource Deletion
        if has_id:
            item_entry = {"name": id_or_name}
            if dry_run:
                return {
                    "items": [{"item": item_entry, "deleted": False}],
                    "errors": {"total": 0},
                    "dry_run": True,
                }
            path = self._resolve_path(endpoint, id_or_name)
            api_resp = self.request("DELETE", path)
            deleted_flag = bool(api_resp.get("deleted", True)) if isinstance(api_resp, dict) else True
            return {
                "items": [{"item": item_entry, "deleted": deleted_flag}],
                "errors": {"total": int(not deleted_flag)},
            }

        # Mode 2: Filter-based Discovery or Mode 3: Explicit Batch List
        if has_filters:
            self._validate_delete_filters(norm_endpoint, filter_params)
            search_res = self.get(endpoint, params=filter_params)
            raw_items = search_res.get("items", []) if isinstance(search_res, dict) else []
            targets: list[dict[str, Any]] = [
                {"name": x["name"]} if "name" in x else {"id": x["id"]}
                for x in raw_items
                if isinstance(x, dict) and ("name" in x or "id" in x)
            ]
        else:
            if not items:
                raise ValueError("items must not be empty")
            targets = [{"name": itm} if isinstance(itm, str) else dict(itm) for itm in items]

        if dry_run:
            return {
                "items": [{"item": t, "deleted": False} for t in targets],
                "errors": {"total": 0},
                "dry_run": True,
            }

        # Circuit breaker safety check
        if self.DELETE_MAX_MATCHES is not None and len(targets) > self.DELETE_MAX_MATCHES:
            raise ValueError(
                f"Refusing to delete {len(targets)} items: exceeds DELETE_MAX_MATCHES={self.DELETE_MAX_MATCHES}. Use dry_run=True to review the matched items."
            )

        if not targets:
            return {"items": [], "errors": {"total": 0}}

        if norm_endpoint in SINGLE_DELETE_ONLY_ENDPOINTS:
            return self._delete_sequential(endpoint, targets)
        return self._delete_batches(delete_path, targets, chunk_size)

    # =========================================================================
    # Convenience Wrappers
    # =========================================================================

    def upload(
        self,
        endpoint: str,
        file: str | PathLike[str] | IO[bytes] | bytes,
        *,
        field_name: str = "file",
        filename: str | None = None,
        content_type: str | None = None,
        id_or_name: str | None = None,
        params: Mapping[str, Any] | None = None,
        form_data: Mapping[str, Any] | None = None,
    ) -> Any:
        """Upload a file using multipart/form-data (e.g. SpoofProtection.TRUSTED_MACS_IMPORT).

        Args:
            endpoint: Target upload endpoint (e.g. SpoofProtection.TRUSTED_MACS_IMPORT).
            file: Local file path, open binary file-like object, or raw file bytes.
            field_name: Multipart form field name (default: "file").
            filename: Optional filename override sent in Content-Disposition.
            content_type: Optional MIME type override (inferred for .csv / .txt when omitted).
            id_or_name: Optional path identifier if the target path is parameterized.
            params: Optional query parameters dictionary.
            form_data: Optional additional multipart form fields.

        Returns:
            Decoded response from the firewall.

        """
        if isinstance(file, (str, PathLike)):
            file_path = Path(file)
            resolved_name = filename or file_path.name
            resolved_type = content_type or _UPLOAD_CONTENT_TYPES.get(
                file_path.suffix.lower(), "application/octet-stream"
            )
            with file_path.open("rb") as fh:
                return self.post(
                    endpoint,
                    id_or_name=id_or_name,
                    params=params,
                    files={field_name: (resolved_name, fh, resolved_type)},
                    form_data=form_data,
                )

        resolved_name = (
            filename or "upload.csv"
            if isinstance(file, bytes)
            else filename or Path(str(getattr(file, "name", "upload.csv"))).name
        )

        resolved_type = content_type or _UPLOAD_CONTENT_TYPES.get(
            Path(resolved_name).suffix.lower(), "application/octet-stream"
        )
        return self.post(
            endpoint,
            id_or_name=id_or_name,
            params=params,
            files={field_name: (resolved_name, file, resolved_type)},
            form_data=form_data,
        )

    def move(self, endpoint: str, data: MovePayload | Mapping[str, Any]) -> Any:
        """Reposition a rule or route within an ordered rulebase using the 'move' action.

        Directly issues a POST request to f"{endpoint}/move".

        Args:
            endpoint: Rule or route endpoint (e.g. Firewall.RULES_IPV4, Nat.RULES_IPV4,
                SdWan.ROUTES_IPV4, TlsInspection.RULES_IPV4).
            data: Move specification containing name (or id for TlsInspection.RULES_IPV4),
                position ("top", "bottom", "before", or "after"), and
                referenceItem (required when position is "before" or "after").

        Returns:
            Decoded response from the firewall.

        """
        path = f"{endpoint.rstrip('/')}/move"
        return self.request("POST", path, json_data=dict(data))

    def test_connection(
        self,
        endpoint: str,
        data: Mapping[str, Any] | None = None,
        *,
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        """Test connection to an authentication server, SMS gateway, or threat feed.

        Directly issues a POST request to f"{endpoint}/test-connection".

        Args:
            endpoint: Base server or service endpoint (e.g. Authentication.SERVERS_ACTIVE_DIRECTORY,
                Authentication.SERVERS_LDAP, Authentication.SERVERS_RADIUS,
                Authentication.SERVERS_TACACS, Authentication.SERVERS_GENERIC_IDP_SSO,
                Authentication.GUEST_USER_SETTINGS_SMS_GATEWAYS,
                ActiveThreatResponse.THIRDPARTY_THREAT_FEEDS).
            data: Optional dictionary containing server parameters matching the endpoint's
                OpenAPI test-connection request schema.
            params: Optional query parameters dictionary.

        Returns:
            Decoded response from the firewall indicating connection test outcome.

        """
        path = f"{endpoint.rstrip('/')}/test-connection"
        return self.request(
            "POST",
            path,
            params=params,
            json_data=dict(data) if data is not None else None,
        )


__all__ = ["SFOSClient"]

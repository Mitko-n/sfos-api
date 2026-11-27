"""Typed response and payload structures for Sophos Firewall OS (SFOS) API operations."""

from __future__ import annotations

from typing import Any, Literal, NotRequired, TypedDict

MovePosition = Literal["top", "bottom", "before", "after"]


class PagesInfo(TypedDict, total=False):
    """Pagination metadata returned by numbered or cursor-paginated SFOS collections."""

    current: int
    size: int
    maxSize: int
    total: int
    items: int
    fromKey: str
    nextKey: str | None


class PagedResponse(TypedDict):
    """Standard SFOS collection response containing items and optional pagination metadata."""

    items: list[dict[str, Any]]
    pages: NotRequired[PagesInfo]


class DeleteErrorSummary(TypedDict):
    """Error count summary returned by batch or aggregated delete responses."""

    total: int


class BatchDeleteItemResult(TypedDict):
    """Per-item outcome entry returned in a batch or aggregated delete response."""

    item: dict[str, Any]
    deleted: NotRequired[bool]
    error: NotRequired[dict[str, Any]]


class BatchDeleteResponse(TypedDict):
    """Response shape returned by SFOSClient.delete()."""

    items: list[BatchDeleteItemResult]
    errors: DeleteErrorSummary
    dry_run: NotRequired[bool]


class MovePayload(TypedDict):
    """Payload accepted by SFOSClient.move() rulebase reordering endpoints."""

    name: NotRequired[str]
    id: NotRequired[str]
    position: MovePosition
    referenceItem: NotRequired[dict[str, str]]


class ImportSummary(TypedDict):
    """Aggregate summary counters returned by Trusted MAC import."""

    total: int
    imported: int
    errors: int


class ImportTrustedMacsResponse(TypedDict):
    """Response returned by POST /spoof-protection/trusted-macs/import."""

    summary: ImportSummary
    items: list[dict[str, Any]]


__all__ = [
    "BatchDeleteItemResult",
    "BatchDeleteResponse",
    "DeleteErrorSummary",
    "ImportSummary",
    "ImportTrustedMacsResponse",
    "MovePayload",
    "MovePosition",
    "PagedResponse",
    "PagesInfo",
]

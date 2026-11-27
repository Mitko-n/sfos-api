"""Synchronize and validate OpenAPI-derived client metadata and docs from firewall_config_openapi.yaml."""

from __future__ import annotations

import argparse
import functools
import re
import sys
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

import sfos_api.endpoints as ep  # noqa: E402

DEFAULT_SPEC_PATH = REPO_ROOT / "docs" / ".sophos_firewall_api_docs" / "firewall_config_openapi.yaml"
METADATA_OUTPUT_PATH = REPO_ROOT / "src" / "sfos_api" / "_spec_metadata.py"
ENDPOINTS_DOC_PATH = REPO_ROOT / "docs" / "endpoints_reference.md"

STANDARD_DELETE_FILTERS = frozenset({"nameContains", "nameNotEquals"})
TYPE_ENUM_DISPLAY = "`type` (`tcpOrUdp`, `ip`, `icmp`, `icmpv6`)"


def _resolve_schema(
    schema: dict[str, Any], schemas: dict[str, Any], seen: frozenset[str] = frozenset()
) -> dict[str, Any]:
    """Recursively dereference local component $ref schemas safely."""
    if "$ref" in schema:
        ref_name = schema["$ref"].split("/")[-1]
        if ref_name in seen:
            return {}
        return _resolve_schema(schemas.get(ref_name, {}), schemas, seen | {ref_name})
    resolved = dict(schema)
    if "properties" in resolved and isinstance(resolved["properties"], dict):
        resolved["properties"] = {
            key: _resolve_schema(val, schemas, seen) if isinstance(val, dict) else val
            for key, val in resolved["properties"].items()
        }
    if "items" in resolved and isinstance(resolved["items"], dict):
        resolved["items"] = _resolve_schema(resolved["items"], schemas, seen)
    return resolved


@functools.lru_cache(maxsize=1)
def load_openapi_spec(spec_path: Path = DEFAULT_SPEC_PATH) -> dict[str, Any]:
    """Load and cache the OpenAPI specification using CSafeLoader."""
    return yaml.load(spec_path.read_text(encoding="utf-8"), Loader=yaml.CSafeLoader)


def extract_metadata(spec_path: Path = DEFAULT_SPEC_PATH) -> dict[str, Any]:
    """Extract normalized OpenAPI endpoint metadata needed by SFOSClient."""
    spec = load_openapi_spec(spec_path)
    paths: dict[str, Any] = spec.get("paths", {})
    schemas: dict[str, Any] = spec.get("components", {}).get("schemas", {})

    defined_endpoints = sorted({str(member) for name in ep.__all__ for member in getattr(ep, name)})

    delete_batch_limits: dict[str, int] = {}
    single_delete_only: set[str] = set()
    endpoint_delete_filters: dict[str, frozenset[str]] = {}
    cursor_paginated_collections: set[str] = set()
    non_paginated_collections: set[str] = set()
    collection_query_params: dict[str, frozenset[str]] = {}

    for ep_path in defined_endpoints:
        del_path = f"{ep_path}/delete"
        if del_path in paths and "post" in paths[del_path]:
            rb_schema = _resolve_schema(
                paths[del_path]["post"]
                .get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {}),
                schemas,
            )
            max_items = rb_schema.get("maxItems")
            if max_items is None and isinstance(rb_schema.get("properties"), dict):
                for prop_val in rb_schema["properties"].values():
                    if isinstance(prop_val, dict) and prop_val.get("type") == "array":
                        max_items = prop_val.get("maxItems")
            if max_items is not None and max_items != 50:
                delete_batch_limits[ep_path] = int(max_items)
        else:
            has_single_delete = any(
                f"{ep_path}/{param}" in paths and "delete" in paths[f"{ep_path}/{param}"]
                for param in ("{idOrName}", "{name}", "{id}")
            )
            if has_single_delete:
                single_delete_only.add(ep_path)

        path_item = paths.get(ep_path, {})
        get_op = path_item.get("get") if isinstance(path_item, dict) else None
        if isinstance(get_op, dict):
            query_names = {
                prm["name"]
                for prm in path_item.get("parameters", []) + get_op.get("parameters", [])
                if isinstance(prm, dict) and prm.get("in") == "query"
            }
            collection_query_params[ep_path] = frozenset(query_names)

            resp_schema = _resolve_schema(
                get_op.get("responses", {})
                .get("200", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {}),
                schemas,
            )
            resp_props = resp_schema.get("properties", {}) if isinstance(resp_schema.get("properties"), dict) else {}
            pages_schema = resp_props.get("pages", {})
            pages_props = pages_schema.get("properties", {}) if isinstance(pages_schema, dict) else {}
            if "nextKey" in pages_props or "fromKey" in pages_props:
                cursor_paginated_collections.add(ep_path)
            elif "items" in resp_props and "page" not in query_names:
                non_paginated_collections.add(ep_path)

            has_any_delete = del_path in paths or ep_path in single_delete_only
            if has_any_delete:
                filters = frozenset(query_names - {"page", "pageSize", "pageTotal", "fromKey", "sort"})
                if filters != STANDARD_DELETE_FILTERS:
                    endpoint_delete_filters[ep_path] = filters

    return {
        "DELETE_BATCH_LIMITS": dict(sorted(delete_batch_limits.items())),
        "SINGLE_DELETE_ONLY_ENDPOINTS": sorted(single_delete_only),
        "ENDPOINT_DELETE_FILTERS": dict(sorted((k, sorted(v)) for k, v in endpoint_delete_filters.items())),
        "CURSOR_PAGINATED_ENDPOINTS": sorted(cursor_paginated_collections),
        "NON_PAGINATED_COLLECTION_ENDPOINTS": sorted(non_paginated_collections),
        "COLLECTION_QUERY_PARAMS": dict(sorted((k, sorted(v)) for k, v in collection_query_params.items())),
    }


def _format_frozenset(items: list[str], indent: int = 4) -> str:
    if not items:
        return "frozenset()"
    pad = " " * (indent + 4)
    closing = " " * indent
    lines = [f"{pad}{item!r}," for item in items]
    return "frozenset({\n" + "\n".join(lines) + f"\n{closing}}})"


def _format_frozenset_inline(items: list[str]) -> str:
    if not items:
        return "frozenset()"
    joined = ", ".join(repr(item) for item in items)
    return f"frozenset({{{joined}}})"


def render_metadata_module(metadata: dict[str, Any]) -> str:
    """Render deterministic Python source for src/sfos_api/_spec_metadata.py."""
    lines = [
        '"""Auto-generated OpenAPI metadata maps for SFOSClient.',
        "",
        "Generated from docs/.sophos_firewall_api_docs/firewall_config_openapi.yaml via",
        "scripts/sync_openapi_metadata.py. Do not edit by hand.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from typing import Final",
        "",
        "# Endpoint-specific maxItems overrides on POST .../delete (default is 50).",
        "DELETE_BATCH_LIMITS: Final[dict[str, int]] = {",
    ]
    for path, limit in metadata["DELETE_BATCH_LIMITS"].items():
        lines.append(f"    {path!r}: {limit},")
    lines.extend(
        [
            "}",
            "",
            "# Endpoints supporting DELETE /{idOrName} without a POST .../delete batch route.",
            f"SINGLE_DELETE_ONLY_ENDPOINTS: Final[frozenset[str]] = {_format_frozenset(metadata['SINGLE_DELETE_ONLY_ENDPOINTS'], indent=0)}",
            "",
            "# Per-endpoint query filters allowed by filter-mode delete() when different from",
            "# {'nameContains', 'nameNotEquals'}.",
            "ENDPOINT_DELETE_FILTERS: Final[dict[str, frozenset[str]]] = {",
        ]
    )
    for path, filters in metadata["ENDPOINT_DELETE_FILTERS"].items():
        lines.append(f"    {path!r}: {_format_frozenset_inline(filters)},")
    lines.extend(
        [
            "}",
            "",
            "# Collection GET endpoints using cursor pagination (fromKey / nextKey in pages).",
            f"CURSOR_PAGINATED_ENDPOINTS: Final[frozenset[str]] = {_format_frozenset(metadata['CURSOR_PAGINATED_ENDPOINTS'], indent=0)}",
            "",
            "# Collection GET endpoints omitting page/pageSize/pageTotal query params in OpenAPI.",
            f"NON_PAGINATED_COLLECTION_ENDPOINTS: Final[frozenset[str]] = {_format_frozenset(metadata['NON_PAGINATED_COLLECTION_ENDPOINTS'], indent=0)}",
            "",
            "# Exact OpenAPI-declared query parameter names for collection GET endpoints.",
            "COLLECTION_QUERY_PARAMS: Final[dict[str, frozenset[str]]] = {",
        ]
    )
    for path, qparams in metadata["COLLECTION_QUERY_PARAMS"].items():
        lines.append(f"    {path!r}: {_format_frozenset_inline(qparams)},")
    lines.extend(
        [
            "}",
            "",
            "__all__ = [",
            '    "COLLECTION_QUERY_PARAMS",',
            '    "CURSOR_PAGINATED_ENDPOINTS",',
            '    "DELETE_BATCH_LIMITS",',
            '    "ENDPOINT_DELETE_FILTERS",',
            '    "NON_PAGINATED_COLLECTION_ENDPOINTS",',
            '    "SINGLE_DELETE_ONLY_ENDPOINTS",',
            "]",
            "",
        ]
    )
    return "\n".join(lines)


def _format_query_list(qparams: set[str], path: str) -> str:
    order = ["nameContains", "nameNotEquals", "name", "filter", "sort", "type", "page", "pageSize", "pageTotal"]
    ordered = [q for q in order if q in qparams] + sorted(qparams - set(order))
    parts = [TYPE_ENUM_DISPLAY if (q == "type" and path == "/network/services") else f"`{q}`" for q in ordered]
    return "Query: " + ", ".join(parts)


def sync_endpoints_doc(spec_path: Path = DEFAULT_SPEC_PATH, doc_path: Path = ENDPOINTS_DOC_PATH) -> int:
    """Update Query: clauses in docs/endpoints_reference.md to list all OpenAPI query params."""
    spec = load_openapi_spec(spec_path)
    paths: dict[str, Any] = spec.get("paths", {})
    lines = doc_path.read_text(encoding="utf-8").splitlines()
    changed = 0
    out_lines: list[str] = []

    row_re = re.compile(
        r"^(\|\s*`[A-Za-z0-9_]+\.[A-Z0-9_]+`\s*\|\s*`([^`]+)`\s*\|[^|]+\|[^|]+\|[^|]+\|\s*)([^|]+?)(\s*\|\s*[^|]+\|\s*)$"
    )
    for line in lines:
        match = row_re.match(line)
        if not match:
            out_lines.append(line)
            continue
        prefix, path, params_col, suffix = match.groups()
        spec_qparams: set[str] = set()
        candidates = [path] + [c for c in (f"{path}/{{idOrName}}", f"{path}/{{name}}", f"{path}/{{id}}") if c in paths]
        for candidate in candidates:
            pi = paths.get(candidate, {})
            for p in pi.get("parameters", []):
                if p.get("in") == "query":
                    spec_qparams.add(p["name"])
            for hm in ("get", "post", "patch", "put", "delete"):
                if hm in pi:
                    for p in pi[hm].get("parameters", []):
                        if p.get("in") == "query":
                            spec_qparams.add(p["name"])

        if not spec_qparams:
            out_lines.append(line)
            continue

        new_query = _format_query_list(spec_qparams, path)
        body_split = re.split(r"(<br>\s*Body(?: discriminator)?:.*)", params_col, maxsplit=1)
        head = body_split[0]
        tail = body_split[1] if len(body_split) > 1 else ""
        if "Query:" in head:
            new_head = re.sub(r"Query:.*$", new_query, head)
        else:
            new_head = f"{head}<br>{new_query}" if head and not head.startswith("None") else new_query

        new_params = f"{new_head}{tail}"
        if new_params != params_col:
            changed += 1
        out_lines.append(f"{prefix}{new_params}{suffix}")

    if changed:
        doc_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sync OpenAPI metadata maps from firewall_config_openapi.yaml.")
    parser.add_argument("--check", action="store_true", help="Exit non-zero if _spec_metadata.py is out of sync.")
    parser.add_argument(
        "--sync-docs", action="store_true", help="Also sync Query: parameters in docs/endpoints_reference.md."
    )
    args = parser.parse_args(argv)

    metadata = extract_metadata()
    rendered = render_metadata_module(metadata)

    if args.check:
        if not METADATA_OUTPUT_PATH.exists():
            print(f"ERROR: {METADATA_OUTPUT_PATH} does not exist. Run scripts/sync_openapi_metadata.py.")
            return 1
        current = METADATA_OUTPUT_PATH.read_text(encoding="utf-8")
        if current != rendered:
            print(f"ERROR: {METADATA_OUTPUT_PATH} is out of date with {DEFAULT_SPEC_PATH}.")
            return 1
        print(f"OK: {METADATA_OUTPUT_PATH.relative_to(REPO_ROOT)} is up to date.")
        return 0

    METADATA_OUTPUT_PATH.write_text(rendered, encoding="utf-8")
    print(f"Updated {METADATA_OUTPUT_PATH.relative_to(REPO_ROOT)}.")

    if args.sync_docs:
        updated_rows = sync_endpoints_doc()
        print(f"Updated {updated_rows} row(s) in {ENDPOINTS_DOC_PATH.relative_to(REPO_ROOT)}.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

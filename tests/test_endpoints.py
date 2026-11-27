"""Tests for StrEnum domain classes and OpenAPI alignment."""

import re
from pathlib import Path

import pytest
import scripts.sync_openapi_metadata as sync_script

import sfos_api.endpoints as ep
from sfos_api import (
    Authentication,
    BatchDeleteResponse,
    Firewall,
    ImportTrustedMacsResponse,
    IntrusionPrevention,
    MovePayload,
    Nat,
    Network,
    PagedResponse,
    Routing,
    SdWan,
    SFOSClient,
    SpoofProtection,
    TlsInspection,
)
from sfos_api.client import (
    ALLOWED_DELETE_FILTERS,
    COLLECTION_QUERY_PARAMS,
    CURSOR_PAGINATED_ENDPOINTS,
    DELETE_BATCH_LIMITS,
    ENDPOINT_DELETE_FILTERS,
    NON_PAGINATED_COLLECTION_ENDPOINTS,
    SINGLE_DELETE_ONLY_ENDPOINTS,
)


def test_strenum_is_string():
    assert isinstance(Network.ZONES, str)
    assert Network.ZONES == "/network/zones"
    assert str(Network.ZONES) == "/network/zones"


def test_domain_constants():
    assert Network.ADDRESSES_IPV4 == "/network/addresses/ipv4"
    assert Firewall.RULES_IPV4 == "/firewall/rules/ipv4"
    assert Nat.RULES_IPV4 == "/nat/rules/ipv4"
    assert Routing.STATIC_UNICAST_ROUTES_IPV4 == "/routing/static-unicast-routes/ipv4"
    assert SdWan.ROUTES_IPV4 == "/sd-wan/routes/ipv4"
    assert TlsInspection.RULES_IPV4 == "/tls-inspection/rules/ipv4"
    assert Network.DHCP_SERVER_LEASES_IPV4 == "/network/dhcp/server/leases/ipv4"
    assert Network.DHCP_SERVER_LEASES_IPV6 == "/network/dhcp/server/leases/ipv6"


def test_authentication_endpoints():
    assert Authentication.SERVERS_RADIUS == "/authentication/servers/radius"
    assert Authentication.SERVERS_LDAP_FETCH_BASE_DN == "/authentication/servers/ldap/fetch-base-dn"


def test_consolidated_endpoints():
    assert IntrusionPrevention.SIGNATURE_ATTRIBUTES == "/intrusion-prevention/signature-attributes"


SPEC_PATH = Path(__file__).resolve().parent.parent / "docs" / ".sophos_firewall_api_docs" / "firewall_config_openapi.yaml"


@pytest.mark.skipif(not SPEC_PATH.is_file(), reason="Local vendor OpenAPI spec excluded from Git repository")
def test_openapi_spec_endpoint_drift():
    """Verify endpoint paths and operation metadata against the bundled OpenAPI document."""
    spec_path = SPEC_PATH
    assert spec_path.is_file(), f"OpenAPI reference is missing: {spec_path}"
    spec = sync_script.load_openapi_spec(spec_path)
    assert isinstance(spec, dict), "OpenAPI reference must contain a YAML mapping"
    spec_paths = spec.get("paths")
    assert isinstance(spec_paths, dict) and spec_paths, "OpenAPI reference must define paths"

    defined_endpoints = {getattr(ep, name)[member.name].value for name in ep.__all__ for member in getattr(ep, name)}
    parameter_names = {parameter for path in spec_paths for parameter in re.findall(r"\{([^}]+)\}", path)}
    supported_operations = {
        "get": "get",
        "post": "post",
        "patch": "patch",
        "delete": "delete",
    }

    def is_covered(path: str) -> bool:
        if path in defined_endpoints:
            return True
        parameterized_parent = re.sub(r"/\{[^/]+\}$", "", path)
        if parameterized_parent in defined_endpoints:
            return True
        for suffix in ("/delete", "/move", "/test-connection"):
            if path.endswith(suffix) and path[: -len(suffix)] in defined_endpoints:
                return True
        return False

    def is_current(endpoint: str) -> bool:
        if endpoint in spec_paths:
            return True
        if any(f"{endpoint}/{{{parameter}}}" in spec_paths for parameter in parameter_names):
            return True
        return any(f"{endpoint}{suffix}" in spec_paths for suffix in ("/delete", "/move", "/test-connection"))

    uncovered = [path for path in sorted(spec_paths) if not is_covered(path)]
    assert uncovered == [], f"Found {len(uncovered)} OpenAPI paths not covered by endpoints.py: {uncovered}"

    stale = [endpoint for endpoint in sorted(defined_endpoints) if not is_current(endpoint)]
    assert stale == [], f"Found {len(stale)} endpoint constants absent from the OpenAPI spec: {stale}"

    invalid_operations: list[str] = []
    invalid_path_parameters: list[str] = []
    unsupported_request_media_types: set[tuple[str, str, str]] = set()
    for path, path_item in spec_paths.items():
        if not isinstance(path_item, dict):
            invalid_operations.append(f"{path}: path item is not a mapping")
            continue
        operations = {
            method: operation
            for method, operation in path_item.items()
            if method in {"get", "post", "put", "patch", "delete", "options", "head", "trace"}
        }
        if not operations:
            invalid_operations.append(f"{path}: no HTTP operations")
            continue

        path_parameters = set(re.findall(r"\{([^}]+)\}", path))
        for method, operation in operations.items():
            if method not in supported_operations or not hasattr(SFOSClient, supported_operations[method]):
                invalid_operations.append(f"{method.upper()} {path}: no matching client operation")
                continue
            if not isinstance(operation, dict):
                invalid_operations.append(f"{method.upper()} {path}: operation is not a mapping")
                continue

            parameters = path_item.get("parameters", []) + operation.get("parameters", [])
            declared_path_parameters: set[str] = {
                str(parameter["name"])
                for parameter in parameters
                if isinstance(parameter, dict) and parameter.get("in") == "path" and parameter.get("name") is not None
            }
            if declared_path_parameters != path_parameters:
                invalid_path_parameters.append(
                    f"{method.upper()} {path}: template={sorted(path_parameters)}, "
                    f"declared={sorted(declared_path_parameters)}"
                )

            request_body = operation.get("requestBody")
            if isinstance(request_body, dict):
                content = request_body.get("content", {})
                if isinstance(content, dict):
                    unsupported_request_media_types.update(
                        (method, path, media_type)
                        for media_type in content
                        if media_type not in {"application/json", "multipart/form-data"}
                    )

    assert invalid_operations == [], f"Invalid or unsupported OpenAPI operations: {invalid_operations}"
    assert invalid_path_parameters == [], (
        f"OpenAPI path-template parameters do not match their declarations: {invalid_path_parameters}"
    )
    assert unsupported_request_media_types == set(), (
        f"OpenAPI request media types unsupported by the client changed: {sorted(unsupported_request_media_types)}"
    )

    # Verify Stage 2 client OpenAPI metadata maps against the OpenAPI spec
    schemas = spec.get("components", {}).get("schemas", {})

    def resolve_schema(schema: dict, seen: frozenset[str] = frozenset()) -> dict:
        if "$ref" in schema:
            ref_name = schema["$ref"].split("/")[-1]
            if ref_name in seen:
                return {}
            return resolve_schema(schemas.get(ref_name, {}), seen | {ref_name})
        resolved = dict(schema)
        if "properties" in resolved:
            resolved["properties"] = {k: resolve_schema(v, seen) for k, v in resolved["properties"].items()}
        if "items" in resolved:
            resolved["items"] = resolve_schema(resolved["items"], seen)
        return resolved

    expected_batch_limits: dict[str, int] = {}
    expected_single_only: set[str] = set()
    expected_filter_overrides: dict[str, frozenset[str]] = {}
    expected_cursor_paginated: set[str] = set()
    expected_non_paginated: set[str] = set()
    expected_collection_query_params: dict[str, frozenset[str]] = {}

    for ep_path in defined_endpoints:
        del_path = f"{ep_path}/delete"
        if del_path in spec_paths and "post" in spec_paths[del_path]:
            rb_schema = resolve_schema(
                spec_paths[del_path]["post"]
                .get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {})
            )
            max_items = rb_schema.get("maxItems")
            if max_items is None and "properties" in rb_schema:
                for prop_val in rb_schema["properties"].values():
                    if isinstance(prop_val, dict) and prop_val.get("type") == "array":
                        max_items = prop_val.get("maxItems")
            if max_items is not None and max_items != 50:
                expected_batch_limits[ep_path] = max_items
        else:
            has_single_delete = any(
                f"{ep_path}/{param}" in spec_paths and "delete" in spec_paths[f"{ep_path}/{param}"]
                for param in ("{idOrName}", "{name}", "{id}")
            )
            if has_single_delete:
                expected_single_only.add(ep_path)

        path_item = spec_paths.get(ep_path, {})
        get_op = path_item.get("get") if isinstance(path_item, dict) else None
        if isinstance(get_op, dict):
            query_names = {
                p["name"]
                for p in path_item.get("parameters", []) + get_op.get("parameters", [])
                if isinstance(p, dict) and p.get("in") == "query"
            }
            expected_collection_query_params[ep_path] = frozenset(query_names)
            resp_schema = resolve_schema(
                get_op.get("responses", {})
                .get("200", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {})
            )
            resp_props = resp_schema.get("properties", {})
            pages_props = (
                resp_props.get("pages", {}).get("properties", {}) if isinstance(resp_props.get("pages"), dict) else {}
            )
            if "nextKey" in pages_props or "fromKey" in pages_props:
                expected_cursor_paginated.add(ep_path)
            elif "items" in resp_props and "page" not in query_names:
                expected_non_paginated.add(ep_path)

            has_any_delete = del_path in spec_paths or ep_path in expected_single_only
            if has_any_delete:
                filters = frozenset(query_names - {"page", "pageSize", "pageTotal", "fromKey", "sort"})
                if filters != ALLOWED_DELETE_FILTERS:
                    expected_filter_overrides[ep_path] = filters

    assert DELETE_BATCH_LIMITS == expected_batch_limits
    assert SINGLE_DELETE_ONLY_ENDPOINTS == frozenset(expected_single_only)
    assert ENDPOINT_DELETE_FILTERS == expected_filter_overrides
    assert CURSOR_PAGINATED_ENDPOINTS == frozenset(expected_cursor_paginated)
    assert NON_PAGINATED_COLLECTION_ENDPOINTS == frozenset(expected_non_paginated)
    assert COLLECTION_QUERY_PARAMS == expected_collection_query_params
    assert hasattr(SFOSClient, "upload")
    assert SpoofProtection.TRUSTED_MACS_IMPORT == "/spoof-protection/trusted-macs/import"
    assert all(cls is not None for cls in (PagedResponse, BatchDeleteResponse, MovePayload, ImportTrustedMacsResponse))

"""Automated drift validation for documentation, metadata sync, and example code."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import httpx
import pytest
import scripts.sync_openapi_metadata as sync_script

import sfos_api.endpoints as ep
from sfos_api import Authentication, Firewall, SFOSClient, SpoofProtection

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = REPO_ROOT / "docs" / ".sophos_firewall_api_docs" / "firewall_config_openapi.yaml"
ENDPOINTS_DOC_PATH = REPO_ROOT / "docs" / "endpoints_reference.md"
EXAMPLES_DIR = REPO_ROOT / "examples"


@pytest.mark.skipif(not SPEC_PATH.is_file(), reason="Local vendor OpenAPI spec excluded from Git repository")
def test_sync_openapi_metadata_check_passes():
    assert sync_script.main(["--check"]) == 0


@pytest.mark.skipif(not SPEC_PATH.is_file(), reason="Local vendor OpenAPI spec excluded from Git repository")
def test_endpoints_reference_doc_matches_openapi():
    spec = sync_script.load_openapi_spec(SPEC_PATH)
    paths: dict = spec["paths"]
    doc_text = ENDPOINTS_DOC_PATH.read_text(encoding="utf-8")

    row_re = re.compile(
        r"^\|\s*\*\*`([A-Za-z0-9_]+\.[A-Z0-9_]+)`\*\*(?:<br>)+\s*`?([^|`]+?)`?\s*\|([^|]+)\|([^|]+)\|([^|]+)\|"
    )
    rows_checked = 0
    mismatches: list[str] = []

    for line_no, line in enumerate(doc_text.splitlines(), 1):
        match = row_re.match(line)
        if not match:
            continue
        rows_checked += 1
        enum_ref, path, methods_col, _sig_col, params_col = match.groups()
        cls_name, attr_name = enum_ref.split(".")
        enum_cls = getattr(ep, cls_name, None)
        if enum_cls is None or not hasattr(enum_cls, attr_name):
            mismatches.append(f"Line {line_no}: missing enum {enum_ref}")
            continue
        if str(getattr(enum_cls, attr_name)) != path:
            mismatches.append(f"Line {line_no}: path mismatch for {enum_ref}")

        doc_methods = set(re.findall(r"`(GET|POST|PATCH|PUT|DELETE)`", methods_col))
        spec_methods: set[str] = set()
        base_item = paths.get(path, {})
        for hm in ("get", "post", "patch", "put", "delete"):
            if hm in base_item:
                spec_methods.add(hm.upper())
        item_path = None
        for cand in (f"{path}/{{idOrName}}", f"{path}/{{name}}", f"{path}/{{id}}"):
            if cand in paths:
                item_path = cand
                for hm in ("get", "patch", "put", "delete"):
                    if hm in paths[cand]:
                        spec_methods.add(hm.upper())
        if f"{path}/delete" in paths and "post" in paths[f"{path}/delete"]:
            spec_methods.add("DELETE")
        if doc_methods != spec_methods:
            mismatches.append(
                f"Line {line_no} ({enum_ref}): HTTP methods {sorted(doc_methods)} != {sorted(spec_methods)}"
            )

        spec_qparams: set[str] = set()
        for candidate in [path] + ([item_path] if item_path else []):
            pi = paths.get(candidate, {})
            for p in pi.get("parameters", []):
                if p.get("in") == "query":
                    spec_qparams.add(p["name"])
            for hm in ("get", "post", "patch", "put", "delete"):
                if hm in pi:
                    for p in pi[hm].get("parameters", []):
                        if p.get("in") == "query":
                            spec_qparams.add(p["name"])

        q_section = re.split(r"<br>\s*Body(?: discriminator)?:", params_col)[0]
        qm = re.search(r"Query:\s*(.+)$", q_section)
        doc_qparams = set(re.findall(r"`([^`]+)`", qm.group(1))) if qm else set()
        if path == "/network/services":
            doc_qparams -= {"tcpOrUdp", "ip", "icmp", "icmpv6"}
        if doc_qparams != spec_qparams:
            mismatches.append(
                f"Line {line_no} ({enum_ref}): Query params {sorted(doc_qparams)} != {sorted(spec_qparams)}"
            )

    assert rows_checked == sum(len(getattr(ep, cls_name)) for cls_name in ep.__all__)
    assert mismatches == [], "docs/endpoints_reference.md drifted from OpenAPI:\n" + "\n".join(mismatches)


@pytest.mark.skipif(not SPEC_PATH.is_file(), reason="Local vendor OpenAPI spec excluded from Git repository")
def test_convenience_wrapper_contracts_match_openapi():
    spec = sync_script.load_openapi_spec(SPEC_PATH)
    paths = spec["paths"]
    requests = []
    responses = {
        "/firewall/rules/ipv4/move": {},
        "/authentication/servers/active-directory/test-connection": {
            "success": True,
            "message": "Connection test succeeded.",
            "code": "connectionSuccess",
        },
        "/spoof-protection/trusted-macs/import": {
            "summary": {"total": 1, "imported": 1, "errors": 0},
            "items": [{"item": {"line": 1, "macAddress": "00:11:22:33:44:55"}, "imported": True}],
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path.removeprefix("/api/firewall-config/v1")
        return httpx.Response(200, json=responses[path])

    client = SFOSClient("sfos.example.com", "test-key", transport=httpx.MockTransport(handler))
    with client:
        client.move(Firewall.RULES_IPV4, {"name": "test-rule", "position": "top"})
        client.test_connection(
            Authentication.SERVERS_ACTIVE_DIRECTORY,
            data={
                "name": "test-ad",
                "serverAddress": {"ipv4Address": "192.0.2.1"},
                "connectionSecurity": "none",
                "port": 389,
                "netBIOSDomain": "EXAMPLE",
                "adminUsername": "test",
                "password": "test",
                "domainName": "example.test",
                "searchQueries": ["dc=example,dc=test"],
            },
        )
        client.upload(SpoofProtection.TRUSTED_MACS_IMPORT, b"00:11:22:33:44:55\n", filename="trusted.csv")

    contracts = (
        ("/firewall/rules/ipv4/move", {"position"}, "application/json"),
        (
            "/authentication/servers/active-directory/test-connection",
            {
                "name",
                "serverAddress",
                "connectionSecurity",
                "port",
                "netBIOSDomain",
                "adminUsername",
                "password",
                "domainName",
                "searchQueries",
            },
            "application/json",
        ),
        ("/spoof-protection/trusted-macs/import", {"file"}, "multipart/form-data"),
    )
    assert len(requests) == len(contracts)
    for request, (path, expected_fields, media_type) in zip(requests, contracts, strict=True):
        operation = paths[path]["post"]
        request_schema = operation["requestBody"]["content"][media_type]["schema"]

        assert request.method == "POST"
        assert request.url.path.removeprefix("/api/firewall-config/v1") == path
        assert expected_fields <= request_schema["properties"].keys()
        if media_type == "application/json":
            body = json.loads(request.content)
            assert request.headers["content-type"] == media_type
            assert set(request_schema.get("required", [])) <= body.keys()
            assert expected_fields <= body.keys()
        else:
            assert request.headers["content-type"].startswith(media_type)
            assert b'name="file"' in request.content

        response_body = responses[path]
        response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        assert set(response_schema.get("required", [])) <= response_body.keys()
        for field, field_schema in response_schema.get("properties", {}).items():
            if field in response_body and field_schema.get("type") == "object":
                assert isinstance(response_body[field], dict)
                assert set(field_schema.get("required", [])) <= response_body[field].keys()
            if field in response_body and field_schema.get("type") == "array":
                assert isinstance(response_body[field], list)
                item_schema = field_schema.get("items", {})
                if item_schema.get("oneOf"):
                    for item in response_body[field]:
                        assert any(set(option.get("required", [])) <= item.keys() for option in item_schema["oneOf"])


def _check_enum_references(tree: ast.AST, source_label: str) -> list[str]:
    enum_classes = {cls_name: getattr(ep, cls_name) for cls_name in ep.__all__}
    errors: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            cls = enum_classes.get(node.value.id)
            if cls is not None and not hasattr(cls, node.attr):
                errors.append(f"{source_label}: unknown enum attribute {node.value.id}.{node.attr}")
    return errors


def test_examples_and_notebooks_valid_syntax_and_symbols():
    nb_paths = sorted(EXAMPLES_DIR.glob("*.ipynb"))
    assert nb_paths, "Expected Jupyter notebooks under examples/"
    errors: list[str] = []

    for nb_path in nb_paths:
        data = json.loads(nb_path.read_text(encoding="utf-8"))
        for idx, cell in enumerate(data.get("cells", [])):
            if cell.get("cell_type") != "code":
                continue
            if cell.get("outputs"):
                errors.append(f"{nb_path.name}#cell-{idx}: committed cell outputs must be stripped")
            if cell.get("execution_count") is not None:
                errors.append(f"{nb_path.name}#cell-{idx}: execution_count must be null")
            src = "".join(cell.get("source", []))
            cleaned = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith(("%", "!")))
            tree = ast.parse(cleaned, filename=f"{nb_path.name}#cell-{idx}")
            errors.extend(_check_enum_references(tree, f"{nb_path.name}#cell-{idx}"))

    for py_path in (EXAMPLES_DIR / "quickstart.py",):
        tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=py_path.name)
        errors.extend(_check_enum_references(tree, py_path.name))

    assert errors == [], "\n".join(errors)

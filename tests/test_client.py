"""Tests for SFOSClient in sfos_api."""

import httpx
import pytest

from sfos_api import (
    Authentication,
    AuthenticationError,
    AuthorizationError,
    BadGatewayError,
    BadRequestError,
    ConflictError,
    DenialOfService,
    Firewall,
    GatewayTimeoutError,
    InternalServerError,
    IpsecVpn,
    Logging,
    Monitoring,
    Network,
    NotFoundError,
    RateLimitError,
    Routing,
    ServiceUnavailableError,
    SFOSApiError,
    SFOSClient,
    SFOSConnectionError,
    SFOSTimeoutError,
    SpoofProtection,
    UnprocessableEntityError,
    Waf,
)


def test_client_init_validation():
    # Invalid host containing scheme
    with pytest.raises(ValueError, match="Do not include a protocol in host"):
        SFOSClient("https://192.168.1.1", "secret")

    # Empty host
    with pytest.raises(ValueError, match="host must not be empty"):
        SFOSClient("", "secret")

    # Empty API key
    with pytest.raises(ValueError, match="api_key must not be empty"):
        SFOSClient("192.168.1.1", "")


def test_client_base_url():
    client_default = SFOSClient("192.168.1.1", "secret")
    assert str(client_default.session.base_url) == "https://192.168.1.1:4444/api/firewall-config/v1/"
    assert client_default.session.timeout == httpx.Timeout(30.0)
    client_default.close()

    client_port = SFOSClient("192.168.1.1", "secret", port=8443)
    assert str(client_port.session.base_url) == "https://192.168.1.1:8443/api/firewall-config/v1/"
    client_port.close()

    client_ipv6 = SFOSClient("2001:db8::1", "secret", port=4444)
    assert str(client_ipv6.session.base_url) == "https://[2001:db8::1]:4444/api/firewall-config/v1/"
    client_ipv6.close()


def test_client_defaults_and_ini_profiles(tmp_path):
    ini_file = tmp_path / "config.ini"
    ini_file.write_text(
        "[firewall]\n"
        "host = 192.168.1.1\n"
        "api_key = token-default\n"
        "\n"
        "[firewall_hq]\n"
        "host = 10.0.1.1\n"
        "api_key = token-hq\n"
        "port = 8443\n"
        "verify_ssl = true\n"
        "timeout = 45.0\n",
        encoding="utf-8",
    )

    with SFOSClient(config_path=ini_file) as client_default:
        assert str(client_default.session.base_url) == "https://192.168.1.1:4444/api/firewall-config/v1/"
        assert client_default.session.headers["Authorization"] == "Bearer token-default"
        assert client_default.session.timeout == httpx.Timeout(30.0)

    with SFOSClient(config_path=ini_file, profile="firewall_hq") as client_hq:
        assert str(client_hq.session.base_url) == "https://10.0.1.1:8443/api/firewall-config/v1/"
        assert client_hq.session.headers["Authorization"] == "Bearer token-hq"
        assert client_hq.session.timeout == httpx.Timeout(45.0)

    with SFOSClient(
        host="10.0.2.1",
        api_key="override-token",
        config_path=ini_file,
        profile="firewall_hq",
        port=4445,
        timeout=15.0,
    ) as client_override:
        assert str(client_override.session.base_url) == "https://10.0.2.1:4445/api/firewall-config/v1/"
        assert client_override.session.headers["Authorization"] == "Bearer override-token"
        assert client_override.session.timeout == httpx.Timeout(15.0)


def test_client_ini_errors(tmp_path):
    missing_file = tmp_path / "missing.ini"
    with pytest.raises(FileNotFoundError, match="Config file not found"):
        SFOSClient(config_path=missing_file)

    ini_file = tmp_path / "config.ini"
    ini_file.write_text("[firewall]\nhost = 192.168.1.1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Profile 'unknown' not found"):
        SFOSClient(config_path=ini_file, profile="unknown")

    with pytest.raises(ValueError, match="api_key must be provided"):
        SFOSClient(config_path=ini_file, profile="firewall")

    with pytest.raises(ValueError, match="host must be provided"):
        SFOSClient()


def test_client_context_manager():
    with SFOSClient("192.168.1.1", "secret") as client:
        assert client.session.headers["Authorization"] == "Bearer secret"
        assert client.session.headers["Accept"] == "application/json"


def test_clean_params():
    params = {"a": 1, "b": None, "c": "val"}
    cleaned = SFOSClient._clean_params(params)
    assert cleaned == {"a": 1, "c": "val"}
    assert SFOSClient._clean_params(None) is None
    assert SFOSClient._clean_params({"a": None}) is None


def test_success_responses():
    req = httpx.Request("GET", "https://example.com")
    resp_200 = httpx.Response(200, request=req, json={"status": "ok"})
    resp_201 = httpx.Response(201, request=req, json={"id": "new-1"})

    SFOSClient._raise_for_error(resp_200)
    SFOSClient._raise_for_error(resp_201)


def test_raise_for_error_custom_messages():
    req = httpx.Request("GET", "https://example.com")

    resp_400 = httpx.Response(400, request=req, json={"message": "Invalid IP", "error": "validationError"})
    with pytest.raises(BadRequestError) as exc_400:
        SFOSClient._raise_for_error(resp_400)
    assert exc_400.value.status_code == 400
    assert str(exc_400.value) == "Invalid IP"
    assert exc_400.value.error == "validationError"

    resp_401 = httpx.Response(401, request=req, json={"message": "Token expired"})
    with pytest.raises(AuthenticationError) as exc_401:
        SFOSClient._raise_for_error(resp_401)
    assert exc_401.value.status_code == 401
    assert str(exc_401.value) == "Token expired"

    resp_403 = httpx.Response(403, request=req, json={"message": "Access denied"})
    with pytest.raises(AuthorizationError) as exc_403:
        SFOSClient._raise_for_error(resp_403)
    assert exc_403.value.status_code == 403
    assert str(exc_403.value) == "Access denied"

    resp_404 = httpx.Response(404, request=req, json={"message": "Resource missing"})
    with pytest.raises(NotFoundError) as exc_404:
        SFOSClient._raise_for_error(resp_404)
    assert exc_404.value.status_code == 404
    assert str(exc_404.value) == "Resource missing"

    resp_409 = httpx.Response(409, request=req, json={"message": "Resource already exists"})
    with pytest.raises(ConflictError) as exc_409:
        SFOSClient._raise_for_error(resp_409)
    assert exc_409.value.status_code == 409
    assert str(exc_409.value) == "Resource already exists"

    resp_500 = httpx.Response(500, request=req, json={"message": "Internal failure"})
    with pytest.raises(InternalServerError) as exc_500:
        SFOSClient._raise_for_error(resp_500)
    assert exc_500.value.status_code == 500
    assert str(exc_500.value) == "Internal failure"


def test_raise_for_error_default_messages():
    req = httpx.Request("GET", "https://example.com")

    resp_400 = httpx.Response(400, request=req, content=b"")
    with pytest.raises(BadRequestError) as exc_400:
        SFOSClient._raise_for_error(resp_400)
    assert str(exc_400.value) == "Bad request."

    resp_401 = httpx.Response(401, request=req, content=b"")
    with pytest.raises(AuthenticationError) as exc_401:
        SFOSClient._raise_for_error(resp_401)
    assert str(exc_401.value) == "Authentication required."

    resp_403 = httpx.Response(403, request=req, content=b"")
    with pytest.raises(AuthorizationError) as exc_403:
        SFOSClient._raise_for_error(resp_403)
    assert str(exc_403.value) == "Authorization required."

    resp_404 = httpx.Response(404, request=req, content=b"")
    with pytest.raises(NotFoundError) as exc_404:
        SFOSClient._raise_for_error(resp_404)
    assert str(exc_404.value) == "Not found."

    resp_409 = httpx.Response(409, request=req, content=b"")
    with pytest.raises(ConflictError) as exc_409:
        SFOSClient._raise_for_error(resp_409)
    assert str(exc_409.value) == "Conflict."

    resp_500 = httpx.Response(500, request=req, content=b"")
    with pytest.raises(InternalServerError) as exc_500:
        SFOSClient._raise_for_error(resp_500)
    assert str(exc_500.value) == "Internal server error."


def test_path_resolution():
    client = SFOSClient("sfos.example.com", "test-api-key")

    # Direct resolution
    assert client._resolve_path(Network.ZONES) == "/network/zones"
    assert client._resolve_path(Network.ZONES, "LAN") == "/network/zones/LAN"

    # With special chars in name
    assert client._resolve_path(Network.ZONES, "DMZ 1") == "/network/zones/DMZ%201"
    assert client._resolve_path(Network.ZONES, "branch/1") == "/network/zones/branch%2F1"

    # Parameterized item and action path resolution
    assert client._resolve_path("/network/zones/{idOrName}", "LAN") == "/network/zones/LAN"
    assert (
        client._resolve_path(Logging.LOG_DESTINATIONS_SYSLOG_SERVERS_BY_ID_OR_NAME_LOGS, "server-1")
        == "/logging/log-destinations/syslog-servers/server-1/logs"
    )

    # Error when parameter is missing
    with pytest.raises(ValueError, match="requires 'id_or_name'"):
        client._resolve_path(Logging.LOG_DESTINATIONS_SYSLOG_SERVERS_BY_ID_OR_NAME_LOGS)
    client.close()


def test_path_resolution_generic_placeholders():
    # Non-idOrName placeholders from the OpenAPI spec are substituted, not appended
    assert (
        SFOSClient._resolve_path(DenialOfService.ATTACKS_BY_FLOOD_ATTACK_TYPE, "syn")
        == "/denial-of-service/attacks/syn"
    )
    assert SFOSClient._resolve_path("/application/apps/{name}", "My App") == "/application/apps/My%20App"
    assert SFOSClient._resolve_path("/example/policies/{id}", "42") == "/example/policies/42"

    with pytest.raises(ValueError, match="path parameter 'floodAttackType'"):
        SFOSClient._resolve_path(DenialOfService.ATTACKS_BY_FLOOD_ATTACK_TYPE)

    with pytest.raises(ValueError, match="multiple path parameters"):
        SFOSClient._resolve_path("/a/{x}/b/{y}", "1")


def _recording_client(items: list[dict]) -> tuple[SFOSClient, list[httpx.Request]]:
    """Return a client whose GET requests return items and record every HTTP request."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(200, json={"items": items, "pages": {"current": 1, "total": 1}})
        return httpx.Response(200, json={"ok": True})

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    return client, calls


def test_delete_rejects_unknown_filters():
    client, calls = _recording_client([{"name": "a"}])
    with client, pytest.raises(ValueError, match="Unsupported delete filter"):
        client.delete(Network.ADDRESSES_IPV4, nameContain="typo")
    assert calls == []  # nothing discovered, nothing deleted


def test_delete_type_filter_is_limited_to_service_endpoint():
    client, calls = _recording_client([{"name": "a"}])
    with client:
        with pytest.raises(ValueError, match="Unsupported delete filter"):
            client.delete(Network.ADDRESSES_IPV4, type="ipv4Range")

        preview = client.delete(Network.SERVICES, type="tcpOrUdp", dry_run=True)

    assert preview["items"] == [{"item": {"name": "a"}, "deleted": False}]
    assert len(calls) == 1
    assert calls[0].method == "GET"
    assert calls[0].url.path.endswith("/network/services")
    assert calls[0].url.params["type"] == "tcpOrUdp"


def test_delete_dry_run_sends_no_delete():
    client, calls = _recording_client([{"name": "Temp_1"}, {"name": "Temp_2"}])
    with client:
        preview = client.delete(Network.ADDRESSES_IPV4, nameContains="Temp_", dry_run=True)
    assert preview["dry_run"] is True
    assert preview["errors"]["total"] == 0
    assert len(preview["items"]) == 2
    assert preview["items"] == [
        {"item": {"name": "Temp_1"}, "deleted": False},
        {"item": {"name": "Temp_2"}, "deleted": False},
    ]
    assert [c.method for c in calls] == ["GET"]


def test_delete_dry_run_single_and_batch():
    client, calls = _recording_client([])
    with client:
        assert client.delete(Network.ADDRESSES_IPV4, "h1", dry_run=True)["items"] == [
            {"item": {"name": "h1"}, "deleted": False}
        ]
        assert client.delete(Network.ADDRESSES_IPV4, items=["a", "b"], dry_run=True)["items"] == [
            {"item": {"name": "a"}, "deleted": False},
            {"item": {"name": "b"}, "deleted": False},
        ]
    assert calls == []


def test_delete_max_matches_guard(monkeypatch):
    client, calls = _recording_client([{"name": f"T{i}"} for i in range(5)])
    monkeypatch.setattr(client, "DELETE_MAX_MATCHES", 3)
    with client:
        # dry_run=True succeeds even when matched items exceed DELETE_MAX_MATCHES
        preview = client.delete(Network.ADDRESSES_IPV4, nameContains="T", dry_run=True)
        assert preview["dry_run"] is True
        assert len(preview["items"]) == 5

        with pytest.raises(ValueError, match="exceeds DELETE_MAX_MATCHES=3"):
            client.delete(Network.ADDRESSES_IPV4, nameContains="T")
    assert [c.method for c in calls] == ["GET", "GET"]  # discovery only, no POST .../delete


def test_delete_signature_matches_read():
    # Parity with read(endpoint, id_or_name="", params=None, **kwargs)
    client, calls = _recording_client([{"name": "match-1"}])
    with client:
        # Positional endpoint + id_or_name
        r1 = client.delete(Network.ADDRESSES_IPV4, "host-1", dry_run=True)
        assert len(r1["items"]) == 1

        # Positional endpoint + empty id_or_name + positional params dict
        r2 = client.delete(Network.ADDRESSES_IPV4, "", {"nameContains": "match"}, dry_run=True)
        assert len(r2["items"]) == 1

        # Direct filter kwargs with empty/default id_or_name
        r3 = client.delete(Network.ADDRESSES_IPV4, nameContains="match", dry_run=True)
        assert len(r3["items"]) == 1
    assert [c.method for c in calls] == ["GET", "GET"]


def test_delete_stream_multipage_loop():
    items_pool = [{"name": f"host-{i}"} for i in range(70)]
    deleted_history: list[dict] = []
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET":
            page = int(request.url.params.get("page", 1))
            size = int(request.url.params.get("pageSize", 100))
            page_slice = items_pool[(page - 1) * size : page * size]
            return httpx.Response(
                200,
                json={
                    "items": page_slice,
                    "pages": {"current": page, "size": len(page_slice), "total": 2, "maxSize": 100},
                },
            )
        if request.method == "POST" and request.url.path.endswith("/delete"):
            import json

            body = json.loads(request.content)
            res_items = []
            for itm in body.get("items", []):
                deleted_history.append(itm)
                res_items.append({"item": itm, "deleted": True})
            return httpx.Response(200, json={"items": res_items, "errors": {"total": 0}})
        return httpx.Response(200, json={})

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    with client:
        res = client.delete(Network.ADDRESSES_IPV4, nameContains="host-")

    assert len(res["items"]) == 70
    assert res["errors"]["total"] == 0
    post_calls = [c for c in calls if c.method == "POST"]
    assert len(post_calls) == 2


def test_delete_chunks_large_batches():
    client, calls = _recording_client([])
    with client:
        res = client.delete(Network.ADDRESSES_IPV4, items=[f"h{i}" for i in range(120)])
    assert len(res["items"]) == 120
    assert res["errors"]["total"] == 0
    assert len(calls) == 3
    assert all(c.url.path.endswith("/network/addresses/ipv4/delete") for c in calls)


def test_crud_mock_calls():
    def handler(request: httpx.Request) -> httpx.Response:
        method = request.method
        path = request.url.path
        if "auto-page" in path:
            page = int(request.url.params.get("page", 1))
            if page == 1:
                return httpx.Response(
                    200,
                    json={
                        "items": [{"id": "1"}, {"id": "2"}],
                        "pages": {"current": 1, "size": 2, "total": 2, "maxSize": 100},
                    },
                )
            else:
                return httpx.Response(
                    200, json={"items": [{"id": "3"}], "pages": {"current": 2, "size": 1, "total": 2, "maxSize": 100}}
                )
        if method == "GET" and "nameContains" in request.url.query.decode():
            return httpx.Response(
                200,
                json={
                    "items": [{"id": "rule-1", "name": "rule-1"}],
                    "pages": {"current": 1, "size": 1, "total": 1, "maxSize": 100},
                },
            )
        return httpx.Response(200, json={"path": path, "method": method})

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))

    # 1. create
    res = client.post(Network.ZONES, {"name": "testZone"})
    assert res["path"] == "/api/firewall-config/v1/network/zones"
    assert res["method"] == "POST"

    # 2. read single item
    res = client.get(Network.ZONES, "LAN")
    assert res["path"] == "/api/firewall-config/v1/network/zones/LAN"
    assert res["method"] == "GET"

    # 3. read collection with auto-pagination
    res = client.get("/auto-page")
    assert len(res["items"]) == 3
    assert res["items"][0]["id"] == "1"
    assert res["items"][2]["id"] == "3"
    assert res["pages"]["total"] == 2

    # 4. update
    res = client.patch(Firewall.RULES_IPV4, "rule-1", data={"description": "Updated"})
    assert res["path"] == "/api/firewall-config/v1/firewall/rules/ipv4/rule-1"
    assert res["method"] == "PATCH"

    # 5. delete single
    res = client.delete(Firewall.RULES_IPV4, "rule-1")
    assert res["items"] == [{"item": {"name": "rule-1"}, "deleted": True}]
    assert res["errors"]["total"] == 0

    # 6. delete batch (with dicts)
    res = client.delete(Firewall.RULES_IPV4, items=[{"id": "rule-1"}, {"id": "rule-2"}])
    assert len(res["items"]) == 2
    assert res["errors"]["total"] == 0

    # 6b. delete batch (with strings)
    res = client.delete(Firewall.RULES_IPV4, items=["rule-1", "rule-2"])
    assert len(res["items"]) == 2
    assert res["errors"]["total"] == 0

    # 6c. delete with query filter (e.g. nameContains)
    res = client.delete(Firewall.RULES_IPV4, nameContains="rule")
    assert len(res["items"]) == 1
    assert res["errors"]["total"] == 0

    # 6d. delete with params dict
    res = client.delete(Network.SERVICES, params={"nameContains": "rule", "type": "tcpOrUdp"})
    assert len(res["items"]) == 1
    assert res["errors"]["total"] == 0

    # 6e. validation: mutually exclusive nameContains and nameNotEquals
    with pytest.raises(ValueError, match="does not allow 'nameContains' and 'nameNotEquals' together"):
        client.delete(Firewall.RULES_IPV4, nameContains="a", nameNotEquals="b")

    # 6f. validation: multiple modes (id_or_name + items)
    with pytest.raises(ValueError, match="Provide exactly one deletion mode"):
        client.delete(Firewall.RULES_IPV4, "rule-1", items=["rule-2"])

    # 7. create standalone action with payload
    res = client.post(Authentication.ADMIN_USER_PASSWORD, data={"password": "abc"})
    assert res["path"] == "/api/firewall-config/v1/authentication/admin-user/password"
    assert res["method"] == "POST"

    # 8. create standalone action without payload
    res = client.post(Network.CELLULAR_WAN_RESET_MODEM)
    assert res["path"] == "/api/firewall-config/v1/network/cellular-wan/reset-modem"
    assert res["method"] == "POST"

    # 9. create parameterized action with in-path placeholder
    res = client.post(Authentication.SERVERS_ACTIVE_DIRECTORY_BY_ID_OR_NAME_FETCH_GROUPS, id_or_name="ad-1")
    assert res["path"] == "/api/firewall-config/v1/authentication/servers/active-directory/ad-1/fetch-groups"
    assert res["method"] == "POST"

    # 10. move (direct convenience wrapper)
    res = client.move(Firewall.RULES_IPV4, {"id": "rule-2", "position": "top"})
    assert res["path"] == "/api/firewall-config/v1/firewall/rules/ipv4/move"
    assert res["method"] == "POST"

    # 11. test_connection (direct convenience wrapper)
    res = client.test_connection(Authentication.SERVERS_ACTIVE_DIRECTORY, data={"serverIp": "10.0.0.1"})
    assert res["path"] == "/api/firewall-config/v1/authentication/servers/active-directory/test-connection"
    assert res["method"] == "POST"
    client.close()


def test_transport_timeout_wrapped():
    def timeout_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Read timed out", request=request)

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(timeout_handler))
    with client, pytest.raises(SFOSTimeoutError) as exc_info:
        client.get(Network.ZONES)
    assert "timed out" in str(exc_info.value).lower()
    assert issubclass(SFOSTimeoutError, SFOSApiError)


def test_transport_connection_error_wrapped():
    def connect_fail_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(connect_fail_handler))
    with client, pytest.raises(SFOSConnectionError) as exc_info:
        client.get(Network.ZONES)
    assert "connection failure" in str(exc_info.value).lower()
    assert issubclass(SFOSConnectionError, SFOSApiError)


def test_rate_limit_error_with_retry_after():
    req = httpx.Request("GET", "https://example.com")
    resp_429 = httpx.Response(429, request=req, headers={"retry-after": "12.5"}, json={"message": "Slow down"})
    with pytest.raises(RateLimitError) as exc_429:
        SFOSClient._raise_for_error(resp_429)
    assert exc_429.value.status_code == 429
    assert exc_429.value.retry_after == 12.5
    assert str(exc_429.value) == "Slow down"


def test_additional_status_code_mappings():
    req = httpx.Request("GET", "https://example.com")

    # 422
    with pytest.raises(UnprocessableEntityError):
        SFOSClient._raise_for_error(httpx.Response(422, request=req, json={"message": "Semantic failure"}))

    # 502
    with pytest.raises(BadGatewayError):
        SFOSClient._raise_for_error(httpx.Response(502, request=req))

    # 503
    with pytest.raises(ServiceUnavailableError):
        SFOSClient._raise_for_error(httpx.Response(503, request=req))

    # 504
    with pytest.raises(GatewayTimeoutError):
        SFOSClient._raise_for_error(httpx.Response(504, request=req))


def test_delete_filter_multibatch_native_response():
    # 120 matching items: discovers via auto-pagination, deletes in 3 batches (50, 50, 20)
    items_pool = [{"name": f"host-{i}"} for i in range(120)]
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET":
            page = int(request.url.params.get("page", 1))
            size = int(request.url.params.get("pageSize", 100))
            page_slice = items_pool[(page - 1) * size : page * size]
            total_pages = (len(items_pool) + size - 1) // size
            return httpx.Response(
                200,
                json={
                    "items": page_slice,
                    "pages": {"current": page, "size": len(page_slice), "total": total_pages, "maxSize": 100},
                },
            )
        if request.method == "POST" and request.url.path.endswith("/delete"):
            import json

            body = json.loads(request.content)
            res_items = [{"item": itm, "deleted": True} for itm in body.get("items", [])]
            return httpx.Response(200, json={"items": res_items, "errors": {"total": 0}})
        return httpx.Response(200, json={})

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    with client:
        res = client.delete(Network.ADDRESSES_IPV4, nameContains="host-")

    # Verifies native API format
    assert "items" in res
    assert "errors" in res
    assert len(res["items"]) == 120
    assert res["errors"]["total"] == 0
    assert all(x["deleted"] is True for x in res["items"])

    # Verifies 3 POST delete calls (50 + 50 + 20)
    post_calls = [c for c in calls if c.method == "POST"]
    assert len(post_calls) == 3


def test_delete_batch_with_partial_failures():
    # Simulates Sophos native response where one item is in-use
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/delete"):
            return httpx.Response(
                200,
                json={
                    "items": [
                        {"item": {"name": "host-1"}, "deleted": True},
                        {
                            "item": {"name": "host-in-use"},
                            "error": {"error": "conflict", "message": "Resource is in use."},
                        },
                    ],
                    "errors": {"total": 1},
                },
            )
        return httpx.Response(200, json={})

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    with client:
        res = client.delete(Network.ADDRESSES_IPV4, items=["host-1", "host-in-use"])

    assert len(res["items"]) == 2
    assert res["items"][0]["deleted"] is True
    assert res["items"][1]["error"]["error"] == "conflict"
    assert res["errors"]["total"] == 1


def test_delete_batch_counts_items_reported_as_not_deleted():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "items": [
                    {"item": {"name": "host-1"}, "deleted": True},
                    {"item": {"name": "host-2"}, "deleted": False},
                ],
                "errors": {"total": 0},
            },
        )

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    with client:
        res = client.delete(Network.ADDRESSES_IPV4, items=["host-1", "host-2"])

    assert res["items"][1]["deleted"] is False
    assert res["errors"]["total"] == 1


def test_delete_batches_preserves_partial_state_on_chunk_exception():
    import json

    chunk_num = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal chunk_num
        chunk_num += 1
        body = json.loads(request.content)
        if chunk_num == 2:
            return httpx.Response(503, json={"error": "serviceUnavailable", "message": "CSC busy", "code": 503})
        return httpx.Response(
            200,
            json={"items": [{"item": itm, "deleted": True} for itm in body["items"]], "errors": {"total": 0}},
        )

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    client.DELETE_BATCH_SIZE = 2
    with client:
        res = client.delete(Network.ADDRESSES_IPV4, items=["h1", "h2", "h3", "h4", "h5"])

    assert len(res["items"]) == 5
    assert res["errors"]["total"] == 2
    assert res["items"][0]["deleted"] is True
    assert res["items"][1]["deleted"] is True
    assert res["items"][2]["error"]["error"] == "serviceUnavailable"
    assert res["items"][3]["error"]["error"] == "serviceUnavailable"
    assert res["items"][4]["deleted"] is True


def test_delete_respects_endpoint_batch_max_items():
    import json

    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        body = json.loads(request.content)
        return httpx.Response(
            200, json={"items": [{"item": itm, "deleted": True} for itm in body["items"]], "errors": {"total": 0}}
        )

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    with client:
        # Monitoring.NETFLOW_COLLECTORS enforces OpenAPI maxItems=5 despite DELETE_BATCH_SIZE=50
        res_small = client.delete(Monitoring.NETFLOW_COLLECTORS, items=[f"nf-{i}" for i in range(12)])
        assert len(res_small["items"]) == 12
        assert [len(json.loads(c.content)["items"]) for c in calls] == [5, 5, 2]

        calls.clear()
        # Firewall.RULES_IPV4 permits up to maxItems=200 when DELETE_BATCH_SIZE is raised
        client.DELETE_BATCH_SIZE = 150
        res_large = client.delete(Firewall.RULES_IPV4, items=[f"fw-{i}" for i in range(250)])
        assert len(res_large["items"]) == 250
        assert [len(json.loads(c.content)["items"]) for c in calls] == [150, 100]


def test_delete_sequential_fallback_when_no_batch_endpoint():
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(
                200, json={"items": [{"name": "dos-1"}, {"name": "dos-in-use"}, {"name": "dos-missing"}]}
            )
        if request.method == "DELETE" and request.url.path.endswith("/dos-in-use"):
            return httpx.Response(409, json={"error": "conflict", "message": "In use"})
        if request.method == "DELETE" and request.url.path.endswith("/dos-missing"):
            return httpx.Response(200, json={"deleted": False})
        if request.method == "DELETE":
            return httpx.Response(200, json={"deleted": True})
        return httpx.Response(404)

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    with client:
        # Filter-mode delete on DenialOfService.POLICIES discovers paginated items and falls back to DELETE /{idOrName}
        res = client.delete(DenialOfService.POLICIES, nameContains="dos-")
        assert res["errors"]["total"] == 2
        assert res["items"] == [
            {"item": {"name": "dos-1"}, "deleted": True},
            {"item": {"name": "dos-in-use"}, "error": {"error": "conflict", "message": "In use"}},
            {"item": {"name": "dos-missing"}, "deleted": False},
        ]
        assert calls[0].method == "GET"
        assert calls[0].url.params["page"] == "1"
        assert [c.method for c in calls[1:]] == ["DELETE", "DELETE", "DELETE"]

        # Single-resource delete also honors deleted=False from server
        single = client.delete(DenialOfService.POLICIES, "dos-missing")
        assert single == {"items": [{"item": {"name": "dos-missing"}, "deleted": False}], "errors": {"total": 1}}


def test_delete_endpoint_specific_filter_validation():
    client, calls = _recording_client([{"name": "p1"}])
    with client:
        # Waf.PROTECTION_POLICIES uses `name`, not `nameContains`
        with pytest.raises(ValueError, match="Unsupported delete filter"):
            client.delete(Waf.PROTECTION_POLICIES, nameContains="p1")
        preview_waf = client.delete(Waf.PROTECTION_POLICIES, name="p1", dry_run=True)
        assert preview_waf["items"] == [{"item": {"name": "p1"}, "deleted": False}]

        # IpsecVpn.SITE_TO_SITE_FAILOVER_GROUPS allows `filter` (but rejects `sort` alone)
        with pytest.raises(ValueError, match="Unsupported delete filter"):
            client.delete(IpsecVpn.SITE_TO_SITE_FAILOVER_GROUPS, sort="name")
        preview_fg = client.delete(IpsecVpn.SITE_TO_SITE_FAILOVER_GROUPS, filter="status:up", dry_run=True)
        assert preview_fg["items"] == [{"item": {"name": "p1"}, "deleted": False}]

        # Filterless deletable endpoints reject filter mode cleanly before sending GET
        with pytest.raises(ValueError, match="does not support query-filter deletion"):
            client.delete(Routing.STATIC_UNICAST_ROUTES_IPV4, nameContains="gw")

    assert len(calls) == 2


def test_read_non_paginated_and_cursor_pagination():
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        path = request.url.path
        if path.endswith("/authentication/servers/ldap"):
            return httpx.Response(200, json={"items": [{"name": "corp-ldap"}]})
        if path.endswith("/authentication/live-users"):
            return httpx.Response(
                200, json={"items": [{"userName": "alice"}], "pages": {"current": 1, "size": 1, "maxSize": 1000}}
            )
        if path.endswith("/network/dhcp/server/leases/ipv4"):
            from_key = request.url.params.get("fromKey")
            if from_key is None:
                return httpx.Response(
                    200,
                    json={
                        "items": [{"leasedIp": "10.0.0.1"}],
                        "pages": {"fromKey": "k0", "nextKey": "k1", "size": 1, "maxSize": 100},
                    },
                )
            if from_key == "k1":
                return httpx.Response(
                    200,
                    json={
                        "items": [{"leasedIp": "10.0.0.2"}],
                        "pages": {"fromKey": "k1", "size": 1, "maxSize": 100},
                    },
                )
        return httpx.Response(404)

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    with client:
        # 1. Non-paginated endpoint does not receive page/pageSize/pageTotal or fabricate `pages`
        ldap_res = client.get(Authentication.SERVERS_LDAP)
        assert ldap_res == {"items": [{"name": "corp-ldap"}]}
        assert dict(calls[-1].url.params) == {}

        # 2. Live endpoint without `total` returns once without error
        live_res = client.get(Authentication.LIVE_USERS)
        assert live_res["items"] == [{"userName": "alice"}]
        assert "total" not in live_res["pages"]

        # 3. Cursor-paginated DHCP leases follow nextKey -> fromKey automatically
        lease_res = client.get(Network.DHCP_SERVER_LEASES_IPV4)
        assert lease_res["items"] == [{"leasedIp": "10.0.0.1"}, {"leasedIp": "10.0.0.2"}]
        assert lease_res["pages"]["size"] == 2
        assert lease_res["pages"]["nextKey"] is None

        # 4. Explicit fromKey performs single-page fetch
        single_lease = client.get(Network.DHCP_SERVER_LEASES_IPV4, fromKey="k1")
        assert single_lease["items"] == [{"leasedIp": "10.0.0.2"}]

        # 5. fromKey rejected on single-resource read
        with pytest.raises(ValueError, match="Pagination parameters are not supported"):
            client.get(Network.ZONES, "LAN", fromKey="k1")


def test_upload_and_multipart_requests(tmp_path):
    from io import BytesIO

    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "summary": {"total": 1, "imported": 1, "errors": 0},
                "items": [{"item": {"line": 1, "macAddress": "00:11:22:33:44:55"}, "imported": True}],
            },
        )

    csv_file = tmp_path / "macs.csv"
    csv_file.write_text("00:11:22:33:44:55\n", encoding="utf-8")

    client = SFOSClient("sfos.example.com", "api-key", transport=httpx.MockTransport(handler))
    with client:
        # 1. Path upload with .csv MIME inference
        res_path = client.upload(SpoofProtection.TRUSTED_MACS_IMPORT, csv_file)
        assert res_path["summary"]["imported"] == 1
        assert calls[-1].headers["content-type"].startswith("multipart/form-data; boundary=")
        assert b"00:11:22:33:44:55" in calls[-1].content
        assert b"text/csv" in calls[-1].content

        # 2. Bytes upload
        res_bytes = client.upload(SpoofProtection.TRUSTED_MACS_IMPORT, b"AA:BB:CC:DD:EE:FF\n", filename="macs.txt")
        assert res_bytes["summary"]["total"] == 1
        assert b"text/plain" in calls[-1].content

        # 3. File-like stream upload
        stream = BytesIO(b"11:22:33:44:55:66\n")
        res_stream = client.upload(SpoofProtection.TRUSTED_MACS_IMPORT, stream, filename="stream.csv")
        assert res_stream["summary"]["total"] == 1

        # 4. Reject mixing JSON body and multipart/form data
        with pytest.raises(ValueError, match="Cannot combine JSON 'data'"):
            client.post(
                SpoofProtection.TRUSTED_MACS_IMPORT, data={"foo": "bar"}, files={"file": ("a.csv", b"x", "text/csv")}
            )
        with pytest.raises(ValueError, match="Cannot combine 'json_data'"):
            client.request(
                "POST",
                SpoofProtection.TRUSTED_MACS_IMPORT,
                json_data={"a": 1},
                files={"file": ("a.csv", b"x", "text/csv")},
            )
        with pytest.raises(ValueError, match="Cannot combine 'json_data'"):
            client.request("POST", SpoofProtection.TRUSTED_MACS_IMPORT, json_data={"a": 1}, data={"x": "1"})


def test_strict_query_validation():
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"items": [], "pages": {"current": 1, "total": 1}})

    client = SFOSClient(
        "sfos.example.com",
        "api-key",
        transport=httpx.MockTransport(handler),
        strict_query_validation=True,
    )
    with client:
        # Allowed params pass cleanly
        client.get(Network.SERVICES, type="tcpOrUdp", nameContains="http")
        client.get(Network.DHCP_SERVER_LEASES_IPV4, fromKey="cursor-1")
        # Unknown/custom endpoint outside OpenAPI is not blocked
        client.get("/custom/mock-endpoint", customFilter="1")

        # Unknown query param rejected locally before request
        with pytest.raises(ValueError, match="Unsupported query parameter"):
            client.get(Network.ZONES, pageSize=50, bogusParam="oops")

        # Non-paginated endpoint rejects pageSize in strict mode
        with pytest.raises(ValueError, match="Unsupported query parameter"):
            client.get(Authentication.SERVERS_LDAP, pageSize=10)

        # Mutually exclusive filters rejected locally
        with pytest.raises(ValueError, match="does not allow 'nameContains' and 'nameNotEquals'"):
            client.get(Firewall.RULES_IPV4, nameContains="a", nameNotEquals="b")

    assert len(calls) == 3

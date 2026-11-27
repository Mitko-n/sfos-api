# Firewall API - API Reference <a id="top"></a>

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)
[![Development Status: Beta 0.8.0](https://img.shields.io/badge/Status-Beta%200.8.0-orange.svg)](https://pypi.org/project/sfos-api/)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Complete technical reference for the `SFOSClient` class, methods, parameters, invocation variants, and exception hierarchy.

The endpoint definitions and documented API operations are checked against the bundled `Sophos Firewall Configuration OpenAPI specification`. Its metadata lists [Sophos Firewall APIs](https://developer.sophos.com) as the contact and identifies the document as OpenAPI 3.0.0 and API version 1.0.0. This repository does not record the upstream revision or retrieval date, so the file should not be assumed to be the latest release. Actual availability can depend on firewall firmware.

The client serializes request bodies as JSON by default and supports `multipart/form-data` uploads (for `SpoofProtection.TRUSTED_MACS_IMPORT`) via `client.upload()` or `files=` on `post()` / `request()`. Payloads are not pre-validated against OpenAPI body schemas; opt-in `strict_query_validation=True` validates collection `GET` query parameter names.

---

## 🧭 Quick Navigation <a id="quick-navigation"></a>

| Category | Method / Topic | Description | Link |
|---|---|---|---|
| **Lifecycle** | **Client Initialization** | Configuration options, SSL, timeout, context manager | [Jump to Client Init](#client-initialization) |
| **Read** | **`client.get()`** | Auto-pagination, filtering, single-page, single-resource | [Jump to get()](#1-get) |
| **Create & Actions** | **`client.post()`** | Standard creation, standalone actions, and parameterized RPCs | [Jump to post()](#2-post) |
| **Update** | **`client.patch()`** | RFC 7396 JSON Merge Patch, singletons, clearing fields | [Jump to patch()](#3-patch) |
| **Delete** | **`client.delete()`** | Single resource deletion, batch deletion | [Jump to delete()](#4-delete) |
| **File Upload** | **`client.upload()`** | Multipart file upload (`SpoofProtection.TRUSTED_MACS_IMPORT`) | [Jump to upload()](#6b-upload) |
| **Rule Reordering** | **`client.move()`** | Direct rulebase reordering (`top`, `bottom`, `before`, `after`) | [Jump to move()](#5-move) |
| **Connection Test** | **`client.test_connection()`** | Direct connectivity & credential testing for directory/AAA servers | [Jump to test_connection()](#6-test_connection) |
| **Low-Level Transport** | **`client.request()`** | Low-level HTTP invocation, custom headers | [Jump to request()](#7-request) |
| **Session Lifecycle** | **`client.close()`** | Session lifecycle management | [Jump to close()](#8-close) |
| **Types & Constants** | **TypedDicts & Constants** | Payload/response `TypedDict` types and batch constants | [Jump to Types & Constants](#types-and-constants) |
| **Exceptions** | **Exception Hierarchy** | HTTP error mappings, error codes, `parse_error`/`parse_errors` | [Jump to Exceptions](#exception-hierarchy) |

**Jump to Section:** [🛠️ Client Initialization](#client-initialization) &nbsp;•&nbsp; [📌 Core CRUD & Actions](#core-crud-methods) &nbsp;•&nbsp; [⚡ Convenience Wrappers](#convenience-wrappers) &nbsp;•&nbsp; [🔌 Low-Level & Lifecycle](#low-level-lifecycle-methods) &nbsp;•&nbsp; [📐 Types & Constants](#types-and-constants) &nbsp;•&nbsp; [🚨 Exception Hierarchy](#exception-hierarchy)

---

<a id="client-initialization"></a>
## 🛠️ Client Initialization & Lifecycle

```python
from sfos_api import SFOSClient

client = SFOSClient(
    host="192.168.1.1",
    api_key="your-api-key",
    port=4444,
    verify_ssl=True,
    timeout=30.0,
)
```

### Constructor Parameters

| Parameter | Type | Default | Description |
|---|---|:---:|---|
| `host` | `str` | *Required* | Firewall IP address or FQDN. **Do not include protocol** (`https://` is automatically enforced). |
| `api_key` | `str` | *Required* | API token generated in Sophos Firewall OS (SFOS) WebAdmin (`Administration > API`). |
| `port` | `int \| None` | `None` | WebAdmin REST API port. Typically `4444`. When `None`, standard HTTPS port (`443`) is used. |
| `verify_ssl` | `bool \| str \| ssl.SSLContext` | `True` | SSL certificate verification. Set to `False` for self-signed certificates, pass a path to a trusted CA bundle file, or provide an `ssl.SSLContext`. |
| `timeout` | `float \| httpx.Timeout` | `30.0` | HTTP request timeout in seconds or an explicit `httpx.Timeout` instance. |
| `transport` | `httpx.BaseTransport \| None` | `None` | Optional custom `httpx` transport (e.g. `httpx.MockTransport` for unit testing). |
| `strict_query_validation` | `bool` | `False` | When `True`, `get()` collection calls validate query parameter names against OpenAPI-declared query params before sending GET requests. |

### Context Manager Pattern (Recommended)

`SFOSClient` supports Python's context manager protocol (`with` statement) to automatically close the underlying HTTP transport:

```python
from sfos_api import SFOSClient, Network

with SFOSClient("192.168.1.1", "your-api-key", port=4444, verify_ssl=True) as client:
    zones = client.get(Network.ZONES)
    print(f"Total zones: {len(zones['items'])}")
# Session is automatically closed upon block exit
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="core-crud-methods"></a>
<a id="client-methods"></a>
## 📌 Core CRUD Methods

The four generic CRUD methods (`get`, `post`, `patch`, `delete`) map client calls to HTTP operations. They handle base URL construction, RFC 3986 path encoding, omission of `None` query values, transparent collection auto-pagination, and RFC 7396 merge-patch semantics for `patch`. They do not validate resource payloads against every OpenAPI schema; use the bundled spec for operation-specific request and response shapes.

<a id="1-get"></a>
### 1. `client.get()`

Fetch a single resource, a filtered query, or an auto-paginated collection.

```python
client.get(
    endpoint: str,
    id_or_name: str = "",
    params: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> Any
```

#### Parameters

| Parameter | Type | Default | Description |
|---|---|:---:|---|
| `endpoint` | `str` | *Required* | Domain endpoint constant (e.g. `Network.ZONES`) or raw API path string. |
| `id_or_name` | `str` | `""` | Identifier or name of a single resource. When provided, single resource lookup is performed. |
| `params` | `Mapping[str, Any] \| None` | `None` | Optional query parameters dictionary (e.g. `{"nameContains": "Server"}`). |
| `**kwargs` | `Any` | — | Additional query parameters passed as keyword arguments (merged with `params`). |

#### Supported Variants

##### Variant A: Transparent Auto-Pagination (Default for Collections)
When reading a paginated collection without specifying `page`, `pageTotal`, or `fromKey`, `client.get()` automatically discovers and aggregates all pages (handling both `page`/`pages.total` numbered pagination and `fromKey`/`pages.nextKey` cursor pagination). Non-paginated OpenAPI collection endpoints are queried once without adding `page`/`pageSize` parameters:

```python
# Fetches all network zones across all pages automatically
zones = client.get(Network.ZONES)
print(f"Retrieved {len(zones['items'])} zones across {zones['pages']['total']} page(s)")
```

##### Variant B: Auto-Pagination with Custom Batch Size
Controls the chunk size per HTTP request during auto-pagination (SFOS supports `1` to `100` per page):

```python
# Fetches all IPv4 firewall rules in chunks of 50 per request
rules = client.get(Firewall.RULES_IPV4, pageSize=50)
```

##### Variant C: Server-Side Query Filtering
Pass filter criteria via `params` or direct keyword arguments:

```python
# Filter using keyword arguments
servers = client.get(Network.ADDRESSES_IPV4, nameContains="Server")

# Filter using params dictionary
active_rules = client.get(
    Firewall.RULES_IPV4,
    params={"nameContains": "LAN_to_WAN", "pageSize": 25},
)
```

##### Variant D: Explicit Single-Page Fetch (Disables Auto-Pagination)
Specify `page` to retrieve only a specific single page:

```python
# Retrieves page 2 only (no subsequent pages fetched)
page_2 = client.get(Network.ADDRESSES_IPV4, page=2, pageSize=25)
print(f"Items on page 2: {len(page_2['items'])}")
```

##### Variant E: Single Resource Read by Name or ID
Pass the resource identifier or name as the second argument:

```python
# Fetch single zone
zone = client.get(Network.ZONES, "LAN")
print(f"Zone type: {zone['type']}")

# Fetch single host object
host = client.get(Network.ADDRESSES_IPV4, "Database_Master")
```

##### Variant F: Parameterized Path Sub-Resource Read
When an endpoint template contains path variables (e.g. `Logging.LOG_DESTINATIONS_SYSLOG_SERVERS_BY_ID_OR_NAME_LOGS` which maps to `/logging/log-destinations/syslog-servers/{idOrName}/logs`), pass the parent identifier as `id_or_name`:

```python
logs_config = client.get(Logging.LOG_DESTINATIONS_SYSLOG_SERVERS_BY_ID_OR_NAME_LOGS, "syslog-server-1")
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="2-post"></a>
### 2. `client.post()`

Create a new configuration resource on the firewall, invoke a standalone action, or execute a parameterized RPC action.

```python
client.post(
    endpoint: str,
    data: Mapping[str, Any] | None = None,
    *,
    id_or_name: str | None = None,
    params: Mapping[str, Any] | None = None,
    files: Any = None,
    form_data: Mapping[str, Any] | None = None,
) -> Any
```

#### Parameters

| Parameter | Type | Default | Description |
|---|---|:---:|---|
| `endpoint` | `str` | *Required* | Domain endpoint constant (e.g. `Network.ADDRESSES_IPV4`, `Authentication.ADMIN_USER_PASSWORD`) or raw path. |
| `data` | `Mapping[str, Any] \| None` | `None` | Optional resource attributes or action parameters sent as JSON body. |
| `id_or_name` | `str \| None` | `None` | Optional identifier for parameterized/nested paths (e.g. `{idOrName}`). |
| `params` | `Mapping[str, Any] \| None` | `None` | Optional query string parameters dictionary. |
| `files` | `Any` | `None` | Optional multipart files mapping/sequence forwarded to `httpx` (mutually exclusive with `data`). |
| `form_data` | `Mapping[str, Any] \| None` | `None` | Optional multipart form fields sent alongside `files` (mutually exclusive with `data`). |

#### Supported Variants

##### Variant A: Standard Collection Resource Creation
```python
new_host = client.post(
    Network.ADDRESSES_IPV4,
    {
        "name": "Web_Server_01",
        "ipv4Address": "192.168.10.50",
        "type": "ipv4Address",
        "description": "Primary web frontend",
    },
)
print("Host created successfully")
```

##### Variant B: Standalone Action RPC Execution
For action endpoints that perform operational commands directly via `POST`:

```python
# Change the built-in administrator password
client.post(
    Authentication.ADMIN_USER_PASSWORD,
    data={"currentPassword": "OldPassword!", "newPassword": "NewPassword!"},
)

# Hardware reset for cellular modem (no payload required)
client.post(Network.CELLULAR_WAN_RESET_MODEM)
```

##### Variant C: Parameterized In-Path Action RPC Execution
Substitutes `{idOrName}` in action templates seamlessly:

```python
# Query security groups from a specific Active Directory server
groups = client.post(
    Authentication.SERVERS_ACTIVE_DIRECTORY_BY_ID_OR_NAME_FETCH_GROUPS,
    id_or_name="HQ_Active_Directory",
)

# Trigger synchronization on a specific threat feed
client.post(
    ActiveThreatResponse.THIRDPARTY_THREAT_FEEDS_BY_ID_OR_NAME_SYNCHRONIZE,
    id_or_name="feed-01",
)
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)


---

<a id="3-patch"></a>
### 3. `client.patch()`

Update an existing resource using **JSON Merge Patch (RFC 7396)** semantics via HTTP `PATCH`.

```python
client.patch(
    endpoint: str,
    id_or_name: str | None = None,
    *,
    data: Mapping[str, Any],
) -> Any
```

#### RFC 7396 Rules:
- Attributes present in `data` are overwritten or added.
- Attributes set to `None` (JSON `null`) are deleted or reset to firewall defaults.
- Omitted attributes remain completely untouched.

#### Parameters

| Parameter | Type | Default | Description |
|---|---|:---:|---|
| `endpoint` | `str` | *Required* | Domain endpoint constant (e.g. `Network.ADDRESSES_IPV4`) or raw path. |
| `id_or_name` | `str \| None` | `None` | Resource identifier or name. Required for collection items; omitted for singletons. |
| `data` | `Mapping[str, Any]` | *Required* | Dictionary of attributes to update. |

#### Supported Variants

##### Variant A: Update Identified Collection Resource
```python
# Updates only the description without overwriting IP address or other fields
client.patch(
    Network.ADDRESSES_IPV4,
    "Web_Server_01",
    data={"description": "Staging frontend node"},
)
```

##### Variant B: Reset / Clear Specific Fields
Pass `None` to clear optional attributes:

```python
client.patch(
    Network.ADDRESSES_IPV4,
    "Web_Server_01",
    data={"description": None},  # Clears description on firewall
)
```

##### Variant C: Singleton Resource Update (No ID)
For global singleton settings endpoints that don't have separate sub-items:

```python
client.patch(
    System.BACKUP_SETTINGS,
    data={"backupStorage": "local", "schedule": {"frequency": "daily", "hour": 2, "minute": 0}},
)
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="4-delete"></a>
### 4. `client.delete()`

Delete one or multiple resources from the firewall.

```python
client.delete(
    endpoint: str,
    id_or_name: str = "",
    params: Mapping[str, Any] | None = None,
    *,
    dry_run: bool = False,
    items: Sequence[str | Mapping[str, Any]] | None = None,
    **kwargs: Any,
) -> dict[str, Any]
```

> [!IMPORTANT]
> Exactly one deletion mode must be provided:
> 1. Single resource identifier (`id_or_name`).
> 2. Explicit batch list (`items`).
> 3. Query filters (`params` or filter kwargs matching the endpoint's OpenAPI query filters).
>
> Providing more or less than one deletion mode raises a `ValueError`.
>
> **Filter Rule:** `nameContains` and `nameNotEquals` are **mutually exclusive** per Sophos REST API specification and cannot be combined together.
>
> **Filter Whitelist:** Query-filter deletions are validated per endpoint against OpenAPI-supported filters (`nameContains`/`nameNotEquals` by default, `type` on `Network.SERVICES`, `name` on `Waf.PROTECTION_POLICIES`, and `filter` on `IpsecVpn.SITE_TO_SITE_FAILOVER_GROUPS`). Endpoints without query filters in OpenAPI reject filter-mode `delete()`, raising a `ValueError` *before* any request is sent.

#### Parameters

| Parameter | Type | Default | Description |
|---|---|:---:|---|
| `endpoint` | `str` | *Required* | Domain endpoint constant or raw API path. |
| `id_or_name` | `str` | `""` | Resource identifier or name for single resource deletion. |
| `params` | `Mapping[str, Any] \| None` | `None` | Optional query filter parameters dictionary (e.g. `{"nameContains": "Temp_"}`). Validated against endpoint-specific OpenAPI filters (`type` for `Network.SERVICES`, `name` for `Waf.PROTECTION_POLICIES`, `filter` for `IpsecVpn.SITE_TO_SITE_FAILOVER_GROUPS`). |
| `dry_run` | `bool` | `False` | Resolve what would be deleted (including filter discovery) without sending any delete request. Returns native response with `{"items": [...], "errors": {"total": 0}, "dry_run": True}`. |
| `items` | `Sequence[str \| Mapping] \| None` | `None` | List of item strings (names/IDs) or item dictionaries for explicit batch deletion. Automatically chunked per OpenAPI `maxItems` (up to `DELETE_BATCH_SIZE`), or run sequentially via `DELETE /{idOrName}` on endpoints without a batch `/delete` route. |
| `**kwargs` | `Any` | — | Additional query filter keyword arguments validated per endpoint. |

> [!NOTE]
> **Limits, Fallbacks & Constants:**
> - `DELETE_BATCH_SIZE = 50`: Default upper batch size per `POST .../delete` request. Each request is capped at `min(DELETE_BATCH_SIZE, spec_maxItems)` using `DELETE_BATCH_LIMITS` (e.g., `5` for `Monitoring.NETFLOW_COLLECTORS`, `8` for `Network.DNS_REQUEST_ROUTES`, `10` for IPsec site-to-site connections, `16` for RADIUS SSO, `20` for CAs, `100`–`200` for syslog/routing/firewall when `DELETE_BATCH_SIZE` is increased, defaulting to `50` elsewhere).
> - `SINGLE_DELETE_ONLY_ENDPOINTS`: Endpoints lacking `POST .../delete` (`DenialOfService.POLICIES`, `Network.INTERFACES_NETWORK_INTERFACES`, `Authentication.CLIENTS_TRANSPARENT_AUTH_SUITE_COLLECTORS`, `Authentication.CLIENTS_TRANSPARENT_AUTH_SUITE_VPN_SOURCE_NETWORKS`) automatically fall back to sequential `DELETE /{idOrName}` calls in `items` and filter modes.
> - `DELETE_MAX_MATCHES = None`: Optional safety guard threshold (disabled by default). If set (e.g., via `client.DELETE_MAX_MATCHES = 100`), a `ValueError` is raised before deletion if matched items exceed the threshold.

#### Supported Variants

##### Variant A: Single Resource Deletion
```python
# Sends HTTP DELETE /network/addresses/ipv4/Web_Server_01
client.delete(Network.ADDRESSES_IPV4, "Web_Server_01")
print("Host deleted")
```

##### Variant B: Batch Multi-Resource Deletion (Strings or Dictionaries)
Accepts either simple name/ID strings or dictionaries. If more than 50 items are passed, `delete()` automatically splits requests into chunks of up to 50:

```python
# Pass simple string names/IDs:
client.delete(
    Network.ADDRESSES_IPV4,
    items=["Old_Host_1", "Old_Host_2", "Old_Host_3"],
)

# Or pass dictionaries:
client.delete(
    Network.ADDRESSES_IPV4,
    items=[{"name": "Old_Host_1"}, {"name": "Old_Host_2"}],
)
print("Batch delete completed")
```

##### Variant C: Query Filter Deletion (`nameContains`, `nameNotEquals`, and service `type`)
Discovers matching resources on the firewall using auto-pagination and server-side filtering, then executes batch deletion:

```python
# Delete all IPv4 address objects containing "Temp_" in their name
client.delete(Network.ADDRESSES_IPV4, nameContains="Temp_")

# The `type` query filter is defined for Network.SERVICES only.
client.delete(
    Network.SERVICES,
    params={"nameContains": "Legacy_", "type": "tcpOrUdp"},
)
```

##### Variant D: Parameterized Resource Deletion
```python
# Deletes a nested sub-resource using template substitution
client.delete("/logging/log-destinations/syslog-servers/{idOrName}", "syslog-deprecated")
```

##### Variant E: Safe Deletion (`dry_run`)
Recommended for any filter-based cleanup on production firewalls:

```python
# Preview — performs discovery only, sends no delete requests
preview = client.delete(Network.ADDRESSES_IPV4, nameContains="Temp_", dry_run=True)
print(f"Items that would be deleted: {len(preview['items'])}")
for entry in preview["items"]:
    print(f"  - {entry['item']}")
```

#### Client Return Structure
`delete()` returns a client-level normalized result. Single-resource deletion and `dry_run` previews are synthesized by the client. Explicit and filter-based batch deletion combine the firewall's per-batch results into one response; the aggregate is not a raw, unchanged Sophos response:

```python
{
    "items": [
        {"item": {"name": "Temp_Host_01"}, "deleted": True},
        {
            "item": {"name": "Temp_Host_02"},
            "error": {"error": "in_use", "message": "Object is referenced by firewall rule #4"},
        },
    ],
    "errors": {"total": 1},
}
```

When `dry_run=True`, the client returns a synthesized preview including `"dry_run": True` and items marked with `"deleted": False`:
```python
{"items": [{"item": {"name": "Temp_Host_01"}, "deleted": False}], "errors": {"total": 0}, "dry_run": True}
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="convenience-wrappers"></a>
## ⚡ Convenience Wrappers

Convenience wrappers are high-level, domain-specific Python helpers for recurring administrative tasks. Instead of constructing raw URL strings and nested payloads manually, convenience wrappers provide typed arguments, validation, and intuitive parameter syntax. Under the hood, convenience wrappers issue HTTP requests directly via `client.request("POST", ...)`.

| Wrapper Method | Direct Wire Route | Purpose | Supported Domains |
|---|---|---|---|
| **`client.move()`** | `POST {endpoint}/move` | Atomic rulebase priority reordering | `Firewall`, `Nat`, `SdWan`, `TlsInspection` |
| **`client.test_connection()`** | `POST {endpoint}/test-connection` | Non-persisting reachability & credential tests | `Authentication`, `ActiveThreatResponse` |
| **`client.upload()`** | `POST {endpoint}` (`multipart/form-data`) | Multipart CSV/TXT file uploads | `SpoofProtection.TRUSTED_MACS_IMPORT` |

---

<a id="5-move"></a>
### 5. `client.move()`

Reposition an ordered rule or route within an SFOS rulebase. SFOS evaluates rules sequentially from top to bottom; `move` allows precise, atomic rule priority reordering.

```python
client.move(endpoint: str, data: Mapping[str, Any]) -> Any
```

> [!NOTE]
> `client.move(endpoint, data)` directly issues an HTTP POST request to `f"{endpoint.rstrip('/')}/move"`.


#### Parameters

| Parameter | Type | Default | Description |
|---|---|:---:|---|
| `endpoint` | `str` | *Required* | Ordered rulebase endpoint constant (see supported list below). |
| `data` | `Mapping[str, Any]` | *Required* | Move specification dictionary containing rule `name` (or `id` for `TlsInspection.RULES_IPV4`), `position`, and optional `referenceItem`. |

#### Move Payload Fields

| Field | Type | Allowed Values | Description |
|---|---|---|---|
| `name` | `str` | Rule name | The name of the rule/route to move (required for `Firewall`, `Nat`, `SdWan`; optional alternative to `id` on `TlsInspection.RULES_IPV4`). |
| `id` | `str` | UUID | Rule UUID (supported on `TlsInspection.RULES_IPV4` as an alternative to `name`). |
| `position` | `str` | `"top"`, `"bottom"`, `"before"`, `"after"` | New position target. |
| `referenceItem` | `dict` | `{"name": "<rule-name>"}` (or `{"id": "<uuid>"}` on `TlsInspection.RULES_IPV4`) | Anchor rule reference (required when `position` is `"before"` or `"after"`; omitted for `"top"` or `"bottom"`). |

#### Supported Rulebase Endpoints

| Domain | Supported Endpoints |
|---|---|
| **Firewall** | `Firewall.RULES_IPV4`, `Firewall.RULES_IPV6` |
| **NAT** | `Nat.RULES_IPV4`, `Nat.RULES_IPV6` |
| **SD-WAN** | `SdWan.ROUTES_IPV4`, `SdWan.ROUTES_IPV6` |
| **TLS Inspection** | `TlsInspection.RULES_IPV4` |

#### Supported Variants

##### Variant A: Move to Boundary (`"top"` or `"bottom"`)
```python
# Move urgent high-priority rule to the top
client.move(
    Firewall.RULES_IPV4,
    {
        "name": "rule-block-malware",
        "position": "top",
    },
)

# Move default catch-all rule to the bottom
client.move(
    Firewall.RULES_IPV4,
    {
        "name": "rule-default-drop",
        "position": "bottom",
    },
)
```

##### Variant B: Move Relative to Another Rule (`"before"` or `"after"`)
```python
# Place new rule immediately ahead of an existing rule
client.move(
    Firewall.RULES_IPV4,
    {
        "name": "rule-web-traffic",
        "position": "before",
        "referenceItem": {"name": "rule-general-outbound"},
    },
)
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="6-test_connection"></a>
### 6. `client.test_connection()`

Execute an on-demand connectivity and credential verification test against an external authentication server, SMS gateway, or third-party threat feed.

```python
client.test_connection(
    endpoint: str,
    data: Mapping[str, Any] | None = None,
    *,
    params: Mapping[str, Any] | None = None,
) -> Any
```

> [!NOTE]
> `client.test_connection(endpoint, data=data, params=params)` directly issues an HTTP POST request to `f"{endpoint.rstrip('/')}/test-connection"`.

#### Parameters

| Parameter | Type | Default | Description |
|---|---|:---:|---|
| `endpoint` | `str` | *Required* | Server or service endpoint constant (see supported list below). |
| `data` | `Mapping[str, Any] \| None` | `None` | Optional server parameters (e.g. host, port, credentials). |
| `params` | `Mapping[str, Any] \| None` | `None` | Optional query parameters. |

#### Supported Service Endpoints

| Domain | Supported Endpoints | Description |
|---|---|---|
| **Active Directory** | `Authentication.SERVERS_ACTIVE_DIRECTORY` | Test Active Directory domain controller authentication & LDAP bind |
| **LDAP** | `Authentication.SERVERS_LDAP` | Test OpenLDAP / directory server connection and search base |
| **RADIUS** | `Authentication.SERVERS_RADIUS` | Test RADIUS server port reachability and shared secret |
| **TACACS+** | `Authentication.SERVERS_TACACS` | Test TACACS+ server connection and admin authorization |
| **Generic IdP SSO** | `Authentication.SERVERS_GENERIC_IDP_SSO` | Test SAML / OIDC identity provider token endpoint |
| **SMS Gateway** | `Authentication.GUEST_USER_SETTINGS_SMS_GATEWAYS` | Test guest user OTP SMS delivery gateway |
| **Threat Feed** | `ActiveThreatResponse.THIRDPARTY_THREAT_FEEDS` | Test third-party threat feed URL reachability and format |

#### Example Usage

```python
# Test connection to an Active Directory domain controller
result = client.test_connection(
    Authentication.SERVERS_ACTIVE_DIRECTORY,
    data={
        "name": "CORP_AD",
        "serverAddress": {"ipv4Address": "10.0.1.10"},
        "connectionSecurity": "none",
        "port": 389,
        "netBIOSDomain": "CORP",
        "adminUsername": "adread",
        "password": "example-password",
        "domainName": "corp.local",
        "searchQueries": ["dc=corp,dc=local"],
    },
)
print("AD Test Result:", result)

# Test connection to an LDAP server
result = client.test_connection(
    Authentication.SERVERS_LDAP,
    data={
        "name": "CORP_LDAP",
        "serverAddress": {"ipv4Address": "10.0.2.20"},
        "version": "3",
        "connectionSecurity": "ssl",
        "port": 636,
        "anonymousLogin": True,
        "authenticationAttribute": "uid",
        "userMapping": {"displayName": "displayName", "email": "mail"},
        "baseDN": "OU=Users,DC=corp,DC=local",
    },
)
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="6b-upload"></a>
### 6b. `client.upload()`

Upload a local file, binary stream, or raw bytes using `multipart/form-data` (for example `SpoofProtection.TRUSTED_MACS_IMPORT`).

```python
client.upload(
    endpoint: str,
    file: str | PathLike[str] | IO[bytes] | bytes,
    *,
    field_name: str = "file",
    filename: str | None = None,
    content_type: str | None = None,
    id_or_name: str | None = None,
    params: Mapping[str, Any] | None = None,
    form_data: Mapping[str, Any] | None = None,
) -> Any
```

```python
from sfos_api import SpoofProtection

result = client.upload(SpoofProtection.TRUSTED_MACS_IMPORT, "trusted_macs.csv")
print(f"Imported {result['summary']['imported']} / {result['summary']['total']} MACs")
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="low-level-lifecycle-methods"></a>
## 🔌 Low-Level Transport & Session Lifecycle

Methods for direct HTTP protocol interaction, custom header injection, unmodeled endpoint execution, and explicit socket disposal.

<a id="7-request"></a>
### 7. `client.request()`

Send a raw HTTP request directly to the firewall. Used for endpoints not covered by higher-level methods or for custom HTTP debugging.

```python
client.request(
    method: str,
    endpoint: str,
    *,
    params: Mapping[str, Any] | None = None,
    json_data: Any = None,
    data: Mapping[str, Any] | None = None,
    files: Any = None,
    headers: Mapping[str, str] | None = None,
) -> Any
```

#### Features:
- Automatically prefixes the firewall base URL (`https://{host}:{port}/api/firewall-config/v1/`).
- Strips `None` values from `params`.
- Handles `204 No Content` gracefully by returning `None`.
- Parses JSON responses automatically or returns raw text if content is not JSON.
- Evaluates HTTP response codes and raises appropriate `SFOSApiError` subclasses.

#### Supported Variants

##### Variant A: Low-Level GET with Custom Headers
```python
settings = client.request(
    "GET",
    "/administration/system-settings",
    headers={"X-Custom-Tracking": "audit-run-42"},
)
```

##### Variant B: Direct Custom POST / PUT
```python
raw_resp = client.request(
    "POST",
    "/network/custom-endpoint",
    json_data={"setting": True},
)
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="8-close"></a>
### 8. `client.close()`

Explicitly close the underlying `httpx.Client` connection pool.

```python
client = SFOSClient("192.168.1.1", "your-api-key", verify_ssl=True)
try:
    data = client.get(Network.ZONES)
finally:
    client.close()
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="types-and-constants"></a>
## 📐 Types, Constants & Error Helpers

### Batch Delete Constants

| Constant | Value | Description |
|---|---|---|
| `DELETE_BATCH_SIZE` | `100` | Maximum number of items sent per batch `POST .../delete` request. |
| `DELETE_MAX_MATCHES` | `5000` | Maximum number of matching items collected by `client.delete()` before raising `ValueError`. |

### Payload & Response TypedDicts

| Symbol | Kind | Description |
|---|---|---|
| `MovePosition` | `Literal["top", "bottom", "before", "after"]` | Allowed target positions for `client.move()`. |
| `MovePayload` | `TypedDict` | Payload accepted by `client.move()` (`position`, optional `name`, `id`, `referenceItem`). |
| `PagesInfo` | `TypedDict` | Pagination metadata (`current`, `size`, `maxSize`, `total`, `items`, `fromKey`, `nextKey`). |
| `PagedResponse` | `TypedDict` | Standard SFOS collection response (`items`, optional `pages: PagesInfo`). |
| `DeleteErrorSummary` | `TypedDict` | Error count summary (`total: int`) in batch delete responses. |
| `BatchDeleteItemResult` | `TypedDict` | Per-item outcome (`item`, optional `deleted`, optional `error`) in batch delete responses. |
| `BatchDeleteResponse` | `TypedDict` | Aggregated response returned by `client.delete()` (`items`, `errors`, optional `dry_run`). |
| `ImportSummary` | `TypedDict` | Aggregate counters (`total`, `imported`, `errors`) returned by Trusted MAC import. |
| `ImportTrustedMacsResponse` | `TypedDict` | Response returned by `SpoofProtection.TRUSTED_MACS_IMPORT` (`summary`, `items`). |

### Error Parsing Helpers

| Helper / Type | Signature | Description |
|---|---|---|
| `SFOSApiErrorInfo` | `dataclass(frozen=True)` | Immutable structured error summary (`message`, `status_code`, `code`, `error`, `item`, `raw`). |
| `parse_error` | `(target: SFOSApiError \| Mapping[str, Any] \| Any) -> SFOSApiErrorInfo` | Convert an exception, error dictionary, or response item into a normalized `SFOSApiErrorInfo`. |
| `parse_errors` | `(target: SFOSApiError \| Mapping[str, Any] \| Sequence[Any]) -> list[SFOSApiErrorInfo]` | Extract all `SFOSApiErrorInfo` entries from an exception, `client.delete()` / `POST .../delete` batch response, or sequence. |

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

<a id="exception-hierarchy"></a>
## 🚨 Exception Hierarchy

All errors raised by `SFOSClient` derive from `SFOSApiError`:

```text
SFOSApiError
 ├── BadRequestError            (HTTP 400)
 ├── AuthenticationError        (HTTP 401)
 ├── AuthorizationError         (HTTP 403)
 ├── NotFoundError              (HTTP 404)
 ├── ConflictError              (HTTP 409)
 ├── UnprocessableEntityError   (HTTP 422)
 ├── RateLimitError             (HTTP 429; exposes retry_after)
 ├── SFOSConnectionError        (HTTP transport / connection failure)
 ├── SFOSTimeoutError           (Connect / read / write timeout)
 └── InternalServerError        (HTTP 500+)
      ├── UnexpectedError       (HTTP 500 subtype)
      ├── BadGatewayError       (HTTP 502)
      ├── ServiceUnavailableError (HTTP 503)
      └── GatewayTimeoutError   (HTTP 504)
```

### Exception Attributes

Every `SFOSApiError` instance exposes structured attributes extracted directly from the firewall's error payload:

| Attribute | Type | Description |
|---|---|---|
| `e.message` | `str` | Human-readable error description. |
| `e.status_code` | `int \| None` | HTTP response status code (e.g. `404`, `409`). |
| `e.code` | `str \| int \| None` | SFOS-specific internal error code returned by the firewall. |
| `e.error` | `str \| None` | Short error identifier or category from firewall response. |
| `e.response_body` | `Any` | Full decoded JSON response body (or raw text) for deep debugging. |
| `e.error_info` | `SFOSApiErrorInfo` | Standardized immutable error summary (`parse_error(e)`). |
| `e.retry_after` | `float \| None` | Parsed `Retry-After` seconds (available on `RateLimitError`). |

Unified helpers `parse_error(target)` and `parse_errors(target)` convert raised `SFOSApiError` exceptions, direct error dictionaries, or `client.delete()` / `POST .../delete` batch responses into `SFOSApiErrorInfo` instances.

### HTTP Status Code & Transport Mapping Table

| Status Code / Condition | Exception Class | Typical Cause |
|---|---|---|
| **`400`** | `BadRequestError` | Invalid JSON syntax, missing required fields, or value schema validation failure. |
| **`401`** | `AuthenticationError` | Missing, expired, or invalid API key. |
| **`403`** | `AuthorizationError` | API key lacks administrator permissions for the requested domain. |
| **`404`** | `NotFoundError` | The requested host, rule, or sub-resource does not exist on the firewall. |
| **`409`** | `ConflictError` | Resource with the same name already exists or is referenced by an active policy. |
| **`422`** | `UnprocessableEntityError` | Request payload is syntactically valid JSON but fails semantic validation. |
| **`429`** | `RateLimitError` | Too many requests / rate limit exceeded (`retry_after` populated from `Retry-After`). |
| **`500`** | `InternalServerError` | Firewall internal server error (`UnexpectedError` is available as a backwards-compatible subclass of `InternalServerError`). |
| **`502`** | `BadGatewayError` | Upstream gateway / proxy failure (`InternalServerError` subclass). |
| **`503`** | `ServiceUnavailableError` | Firewall service temporarily unavailable (`InternalServerError` subclass). |
| **`504`** | `GatewayTimeoutError` | Upstream gateway timeout (`InternalServerError` subclass). |
| **Other `5xx`** | `InternalServerError` | Any unmapped HTTP `5xx` server error. |
| **Network error** | `SFOSConnectionError` | Underlying `httpx` connection/transport error (TLS failure, refused connection, DNS). |
| **Timeout** | `SFOSTimeoutError` | Underlying `httpx` connect, read, or write timeout. |

### Recommended Error Handling Pattern

```python
from sfos_api import (
    BadRequestError,
    ConflictError,
    NotFoundError,
    SFOSApiError,
    SFOSClient,
    Network,
)

with SFOSClient("192.168.1.1", "api-key", verify_ssl=True) as client:
    try:
        client.post(
            Network.ADDRESSES_IPV4,
            {
                "name": "Branch_Gateway",
                "ipv4Address": "10.0.0.1",
                "type": "ipv4Address",
            },
        )
    except ConflictError as e:
        print(f"⚠️ Resource already exists (Code: {e.code}): {e}")
        # Graceful fallback: update existing resource instead
        client.patch(Network.ADDRESSES_IPV4, "Branch_Gateway", data={"ipv4Address": "10.0.0.1"})
    except BadRequestError as e:
        print(f"❌ Invalid parameters: {e}")
        print("Firewall response:", e.response_body)
    except NotFoundError as e:
        print(f"❌ Target not found: {e}")
    except SFOSApiError as e:
        print(f"❌ General SFOS API error [HTTP {e.status_code}]: {e}")
```

[↑ Back to Quick Navigation](#quick-navigation) &nbsp;•&nbsp; [↑ Back to Top](#top)

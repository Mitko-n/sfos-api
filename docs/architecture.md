# Firewall API - Architecture & UML Design Specification <a id="top"></a>

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)
[![Development Status: Beta 0.8.0](https://img.shields.io/badge/Status-Beta%200.8.0-orange.svg)](https://pypi.org/project/sfos-api/)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Comprehensive architectural specification and UML modeling for `sfos-api`, a zero-overhead, synchronous Python 3.11+ client designed for Sophos Firewall OS (SFOS) REST API.

**Beta 0.8.0 API:** The endpoint registry and API-facing documentation are checked against the bundled `Sophos Firewall Configuration OpenAPI specification`. Its metadata lists [Sophos Firewall APIs](https://developer.sophos.com) as the contact and identifies the document as OpenAPI 3.0.0 and API version 1.0.0. This repository does not record the upstream revision or retrieval date, so the file should not be assumed to be the latest release. Firmware versions may expose different operations.

---

## 🧭 Navigation

- [1. Executive Architectural Overview](#1-executive-architectural-overview)
  - [1.1 Core Architectural Principles](#11-core-architectural-principles)
  - [1.2 Target Appliance Internal Architecture (SFOS Kernel & Daemons)](#12-target-appliance-internal-architecture-sfos-kernel--daemons)
- [2. Component & Layered Architecture](#2-component--layered-architecture)
  - [2.1 Detailed Layer Decomposition](#21-detailed-layer-decomposition)
  - [2.2 Wire-Level Request/Response Lifecycle](#22-wire-level-requestresponse-lifecycle)
- [3. Class UML Diagram](#3-class-uml-diagram)
  - [3.1 Structural Design & Class Taxonomy](#31-structural-design--class-taxonomy)
  - [3.2 Invariant Guarantees & Type Safety](#32-invariant-guarantees--type-safety)
- [4. Use Case UML Diagram](#4-use-case-uml-diagram)
  - [4.1 Actor Profiles & Operational Scenarios](#41-actor-profiles--operational-scenarios)
- [5. Sequence Diagrams](#5-sequence-diagrams)
  - [5.1 Client Session Lifecycle & Auto-Pagination](#51-client-session-lifecycle--auto-pagination)
  - [5.2 Resource Creation & RFC 7396 Patch Update](#52-resource-creation--rfc-7396-patch-update)
  - [5.3 Convenience Wrapper: Rule Priority Reordering (Move)](#53-convenience-wrapper-rule-priority-reordering-move)
  - [5.4 Error Interception & Exception Dispatch](#54-error-interception--exception-dispatch)
  - [5.5 Idempotent State Reconciliation Workflow](#55-idempotent-state-reconciliation-workflow)
- [6. Activity & Workflow Diagrams](#6-activity--workflow-diagrams)
  - [6.1 Read & Auto-Pagination Decision Flowchart](#61-read--auto-pagination-decision-flowchart)
  - [6.2 Path Parameter Resolution Algorithm](#62-path-parameter-resolution-algorithm)
  - [6.3 Error Handling & Response Parsing Pipeline](#63-error-handling--response-parsing-pipeline)
- [7. State Transition Diagram](#7-state-transition-diagram)
  - [7.1 Client Lifecycle States & Transitions](#71-client-lifecycle-states--transitions)
- [8. Deployment & Network Topologies](#8-deployment--network-topologies)
  - [8.1 Firewall Communication Architecture](#81-firewall-communication-architecture)
  - [8.2 High Availability (HA) Cluster Topology](#82-high-availability-ha-cluster-topology)
- [9. Security Architecture & Threat Model](#9-security-architecture--threat-model)
  - [9.1 Threat Mitigation Strategies](#91-threat-mitigation-strategies)
  - [9.2 Certificate Verification Configurations](#92-certificate-verification-configurations)
  - [9.3 STRIDE Threat Analysis Matrix](#93-stride-threat-analysis-matrix)
  - [9.4 Enterprise Secrets Management & Key Storage](#94-enterprise-secrets-management--key-storage)
- [10. Concurrency, Performance & Resource Management](#10-concurrency-performance--resource-management)
  - [10.1 Concurrency Model & Thread Safety](#101-concurrency-model--thread-safety)
  - [10.2 Memory Footprint & Socket Optimization](#102-memory-footprint--socket-optimization)
  - [10.3 Connection Pool Management & Socket Tuning](#103-connection-pool-management--socket-tuning)
- [11. Extensibility & Integration Patterns](#11-extensibility--integration-patterns)
  - [11.1 Low-Level Escape Hatch (`client.request`)](#111-low-level-escape-hatch-clientrequest)
  - [11.2 Infrastructure-as-Code (IaC) Integration](#112-infrastructure-as-code-iac-integration)
  - [11.3 Idempotent Desired-State Loop Pattern](#113-idempotent-desired-state-loop-pattern)
  - [11.4 Observability, Auditing & Event Hook Interception](#114-observability-auditing--event-hook-interception)
- [12. Domain Taxonomy & Functional Subsystem Matrix](#12-domain-taxonomy--functional-subsystem-matrix)

---

## 1. Executive Architectural Overview

`sfos-api` is engineered as a lightweight, developer-ergonomic, and high-performance Python client interfacing with the **Sophos Firewall OS (SFOS) Configuration REST API** (`/api/firewall-config/v1/`). Sophos Firewall OS v20+ exposes an OpenAPI 3.0-compliant RESTful interface for provisioning and inspecting system configurations, policies, threat intelligence, and networking objects.

### 1.1 Core Architectural Principles

The architecture of `sfos-api` maps directly to the operational and security characteristics of Sophos Firewall OS:

- **Domain-Scoped `StrEnum` Architecture**: 182 endpoint constants are structured into 27 domain classes inheriting from Python 3.11's `enum.StrEnum`. Constants evaluate directly as native strings (`str`) with zero runtime wrapper overhead, full JSON serializability, and domain-scoped IDE autocomplete (e.g. `Network.ADDRESSES_IPV4`).
- **Synchronous by Default**: Network appliance configuration is inherently linear and order-dependent (e.g. creating zones before interfaces, or placing firewall rules above catch-alls). A clean synchronous API using `httpx.Client` avoids unnecessary event loop complexity in administrative and DevOps automation scripts while preventing parallel write lock contention.
- **RFC 7396 Merge-Patch Semantics**: `SFOSClient.patch()` sends HTTP `PATCH` with a JSON body and applies RFC 7396 merge-patch semantics as documented by the API. The bundled OpenAPI operations declare `application/json` request bodies.
- **Strict HTTPS Enforcement**: Rejects insecure plaintext HTTP schemes at client instantiation to guarantee firewall administrative credentials never traverse networks unencrypted.
- **Resilient Pagination**: Transparently aggregates multi-page collection queries and returns normalized aggregate pagination metadata.
- **Deterministic Resource Routing**: Combines regex template resolution with standard URL path appending and strict RFC 3986 percent-encoding (`urllib.parse.quote(id_or_name, safe="")`).

### 1.2 Target Appliance Request Lifecycle (SFOS REST API)

At a high level, Sophos Firewall OS processes Configuration REST API requests through its WebAdmin HTTPS interface:

```mermaid
graph TD
    subgraph SFOS_Control_Plane["SFOS Management & Control Plane"]
        WebAdmin["HTTPS Management Listener<br/>(Port 4444 TLS Termination)"]
        APIGateway["REST API Gateway<br/>(/api/firewall-config/v1/)"]
        AuthSvc["Authentication & RBAC Verifier<br/>(Bearer API Key validation)"]
        ConfigEngine["Configuration Engine<br/>(Validation & Transaction Serialization)"]
        ConfigStore[("Appliance Configuration Store")]
    end

    subgraph SFOS_Data_Plane["SFOS Packet & Policy Runtime"]
        FirewallEngine["Firewall & NAT Policy Runtime"]
        RoutingEngine["Routing & SD-WAN Engine"]
        VpnEngine["VPN & Tunnel Subsystem"]
    end

    WebAdmin -->|"Routes /api/firewall-config/v1/"| APIGateway
    APIGateway --> AuthSvc
    AuthSvc -->|"Authorized Token"| ConfigEngine
    ConfigEngine <-- "Read / Write Configuration" --> ConfigStore
    ConfigEngine -->|"Applies Policy"| FirewallEngine
    ConfigEngine -->|"Updates Routes"| RoutingEngine
    ConfigEngine -->|"Updates Tunnels"| VpnEngine
```

#### Request Execution Sequence:
1. **TLS Termination & Ingress Routing**: External API requests arrive on the configured WebAdmin HTTPS port (default `4444`) and are routed under `/api/firewall-config/v1/` to the Configuration REST API handler.
2. **API Key & Profile Validation**: The API Gateway inspects the `Authorization: Bearer <token>` header and verifies that the associated administrator profile possesses Read/Write privileges for the targeted resource.
3. **Configuration Validation & Serialization**: Mutative operations are validated against the SFOS schema and serialized against the appliance configuration store so concurrent updates do not leave policy state inconsistent.
4. **Runtime Policy Application**: Once a configuration change is committed, the appliance applies the updated rules, routes, or VPN settings to the active runtime subsystems.
5. **Architectural Consequence**: Issuing high-frequency concurrent writes against the same firewall can cause lock contention and `409 Conflict` errors. The synchronous single-session design of `sfos-api` aligns cleanly with sequential configuration management.

[↑ Back to Top](#top)

---

## 2. Component & Layered Architecture

The system follows a strict 4-tier layered architecture enforcing unidirectional dependency flow:

```mermaid
graph TB
    subgraph Consumer_Layer["1. Consumer Application Layer"]
        CLI["CLI Scripts & DevOps Automation"]
        Notebooks["Interactive Jupyter Notebooks"]
        IaC["Ansible / Terraform Custom Providers"]
        Services["FastAPI / Flask Microservices"]
    end

    subgraph Client_Package["2. sfos_api Package Boundary"]
        subgraph Endpoints_Domain["Endpoints Subsystem (endpoints.py)"]
            NetEnum["Network (StrEnum)"]
            FwEnum["Firewall (StrEnum)"]
            NatEnum["Nat (StrEnum)"]
            AuthEnum["Authentication (StrEnum)"]
            OtherEnums["23 Other Domain StrEnums..."]
        end

        subgraph Core_Client["Client Engine Subsystem (client.py / _spec_metadata.py / types.py)"]
            ClientClass["SFOSClient (CRUD, upload, move, test_connection)"]
            PathResolver["Path Resolver (_resolve_path)"]
            Paginator["Auto-Paginator (Numbered & Cursor)"]
            SpecGuards["OpenAPI Guardrails (_spec_metadata.py)"]
            ErrorTranslator["Error Translator (_raise_for_error)"]
        end

        subgraph Exceptions_Domain["Exception Subsystem (exceptions.py)"]
            BaseErr["SFOSApiError"]
            ClientErrs["BadRequest / Auth / NotFound / Conflict / 422 / 429"]
            ServerErrs["InternalServer / Unexpected / 502 / 503 / 504"]
            TransportErrs["SFOSConnectionError / SFOSTimeoutError"]
            ErrHelpers["SFOSApiErrorInfo / parse_error / parse_errors"]
        end
    end

    subgraph Transport_Layer["3. Transport Layer (httpx)"]
        HttpxSession["httpx.Client (Keep-Alive Pool, TLS Engine, Timeouts)"]
    end

    subgraph Target_System["4. Target Infrastructure Layer"]
        SFOS["Sophos Firewall OS (SFOS) WebAdmin REST API (/api/firewall-config/v1/)"]
    end

    Consumer_Layer --> ClientClass
    Consumer_Layer -.-> Endpoints_Domain
    ClientClass --> PathResolver
    ClientClass --> Paginator
    ClientClass --> ErrorTranslator
    ClientClass --> HttpxSession
    ErrorTranslator --> Exceptions_Domain
    HttpxSession -->|"HTTPS Port 4444 (TLS 1.2+)"| SFOS
```

### 2.1 Detailed Layer Decomposition

1. **Consumer Application Layer**:
   - Represents the calling environment (e.g. interactive Jupyter notebooks, standalone orchestration scripts, or CI/CD pipelines).
   - Consumers interact exclusively with `SFOSClient` and import domain constants from `endpoints.py`.
2. **Endpoints Subsystem (`sfos_api.endpoints`)**:
   - Houses 27 domain classes inheriting from `StrEnum` representing 182 endpoint constants.
   - Independent of the network layer; contains zero business logic and zero external dependencies.
3. **Core Client Engine (`sfos_api.client`)**:
   - **`SFOSClient`**: Orchestrates client operations structured into clear operational tiers:
     - **Core CRUD Primitives**: `get`, `post`, `patch`, `delete` (resource lifecycle management, RFC 7396 merge patching, numbered & cursor auto-pagination, standalone actions, and parameterized actions).
     - **Dedicated Convenience Wrappers**: `upload` (multipart file upload), `move` (rule/route priority reordering), `test_connection` (service connectivity & credential diagnostics).
     - **Low-Level Transport & Lifecycle**: `request` (raw HTTP escape hatch), `close` (connection pool teardown).
   - **Path Resolver**: Replaces parameterized tokens (`{idOrName}`) or appends resource identifiers with proper percent-encoding.
   - **Auto-Paginator**: Manages state across chunked pagination cycles, inspecting `pages.total` and appending `items`.
   - **Error Translator**: Inspects HTTP responses, decodes firewall JSON error bodies, and maps HTTP status codes into concrete exceptions.
4. **Transport Layer (`httpx`)**:
   - Manages connection pooling, HTTP/1.1 keep-alive persistence, TLS certificate validation, and socket timeouts.

### 2.2 Wire-Level Request/Response Lifecycle

Every API interaction in `sfos-api` traverses a rigorous 8-stage pipeline from consumer call to final Python value:

```text
[1. Method Call] ──► [2. Param Sanitization] ──► [3. Path Interpolation] ──► [4. Transport Dispatch]
                                                                                       │
[8. Return Data] ◄── [7. Auto-Pagination]   ◄── [6. Status & Parsing]   ◄── [5. Network I/O]
```

1. **Stage 1 - Ingress Method Invocation**: Consumer triggers a CRUD primitive (e.g. `client.get(Network.ADDRESSES_IPV4, "Web_SRV")`).
2. **Stage 2 - Parameter Normalization & Cleaning (`_clean_params`)**:
   - Collection reads merge explicit `params` dictionaries with variable keyword arguments (`**kwargs`).
   - Omits top-level query entries whose value is `None`, preventing Python `None` from being serialized as the literal string `"None"` in URL parameters.
3. **Stage 3 - Deterministic Path Interpolation (`_resolve_path`)**:
   - Evaluates if the endpoint contains an OpenAPI placeholder (e.g. `/logging/log-destinations/syslog-servers/{idOrName}/logs`).
   - If a placeholder is detected and an identifier is provided, the token is substituted via regular expression replacement.
   - If no placeholder exists but an identifier is provided, the identifier is strictly RFC 3986 percent-encoded via `urllib.parse.quote(id_or_name, safe="")` and appended to the endpoint path.
   - Strips leading forward slashes to ensure seamless joining with the `httpx.Client` base URL (`https://<host>:<port>/api/firewall-config/v1/`).
4. **Stage 4 - Header & Transport Assembly**:
   - Merges default session headers (`Authorization: Bearer <token>`, `Accept: application/json`) with call-specific headers.
   - Encodes JSON request bodies with `httpx`; for `PATCH`, the resulting `application/json` media type matches the bundled OpenAPI request-body declarations.
5. **Stage 5 - Socket Dispatch & Network I/O**:
   - Dispatches the request through the persistent `httpx.Client` connection pool over TLS 1.2/1.3.
   - Reuses warm TCP connections from the pool, avoiding 3-way TCP handshakes and TLS key exchanges on repeated calls.
   - Enforces the configured per-request timeout (default `30.0s`).
6. **Stage 6 - Status Code Verification & Error Translation (`_raise_for_error`)**:
   - Inspects `response.is_error`.
   - If HTTP status >= 400, delegates to `_error_details()` to parse the firewall's error payload.
   - Maps the status code to a domain-specific exception (`BadRequestError`, `NotFoundError`, `ConflictError`, etc.) and raises it immediately.
7. **Stage 7 - Payload Parsing & Auto-Pagination Loop**:
   - If HTTP status is 204 or body is zero bytes, returns `None`.
   - If `Content-Type` is JSON, deserializes the response into native Python dictionaries/lists.
   - For collection reads without explicit pagination parameters, inspects `pages.total`. If `pages.total > 1`, initiates the sequential fetch loop to drain remaining pages.
8. **Stage 8 - Egress Return**:
   - Returns the final consolidated Python data structure to the consumer.

[↑ Back to Top](#top)

---

## 3. Class UML Diagram

```mermaid
classDiagram
    class StrEnum {
        <<standard library>>
    }

    class SFOSClient {
        +str base_url
        +bool strict_query_validation
        +Client session
        +float DEFAULT_TIMEOUT$
        +int DEFAULT_PAGE_SIZE$
        +int DELETE_BATCH_SIZE$
        +int|None DELETE_MAX_MATCHES$
        +Mapping DELETE_BATCH_LIMITS$
        +dict DEFAULT_ERROR_MESSAGES$
        +__init__(host: str, api_key: str, port: int, verify_ssl: bool, timeout: float, transport: BaseTransport, strict_query_validation: bool)
        +__enter__() SFOSClient
        +__exit__(exc_type, exc, tb) None
        +close() None
        +get(endpoint: str, id_or_name: str, params: Mapping, **kwargs) Any
        +post(endpoint: str, data: Mapping, id_or_name: str, params: Mapping, files: Any, form_data: Mapping) Any
        +patch(endpoint: str, id_or_name: str, data: Mapping) Any
        +delete(endpoint: str, id_or_name: str, params: Mapping, dry_run: bool, items: Sequence, **kwargs) dict
        +upload(endpoint: str, file: Any, field_name: str, filename: str, content_type: str, id_or_name: str, params: Mapping, form_data: Mapping) Any
        +move(endpoint: str, data: Mapping) Any
        +test_connection(endpoint: str, data: Mapping, params: Mapping) Any
        +request(method: str, endpoint: str, params: Mapping, json_data: Any, data: Mapping, files: Any, headers: Mapping) Any
        -_resolve_path(endpoint: str, id_or_name: str)$ str
        -_clean_params(params: Mapping)$ dict
        -_error_details(response: Response)$ tuple
        -_raise_for_error(response: Response)$ None
    }

    class Network {
        <<StrEnum>>
        +ADDRESSES_IPV4: "/network/addresses/ipv4"
        +ADDRESSES_FQDN: "/network/addresses/fqdn"
        +ZONES: "/network/zones"
        +INTERFACES_NETWORK_INTERFACES: "/network/interfaces/network-interfaces"
        +SERVICES: "/network/services"
        +SERVICE_GROUPS: "/network/service-groups"
        +CELLULAR_WAN_RESET_MODEM: "/network/cellular-wan/reset-modem"
    }

    class Firewall {
        <<StrEnum>>
        +RULES_IPV4: "/firewall/rules/ipv4"
        +RULES_IPV6: "/firewall/rules/ipv6"
    }

    class Nat {
        <<StrEnum>>
        +RULES_IPV4: "/nat/rules/ipv4"
        +RULES_IPV6: "/nat/rules/ipv6"
    }

    class Authentication {
        <<StrEnum>>
        +USERS: "/authentication/users"
        +USER_GROUPS: "/authentication/user-groups"
        +SERVERS_ACTIVE_DIRECTORY: "/authentication/servers/active-directory"
        +SERVERS_LDAP: "/authentication/servers/ldap"
        +SERVERS_RADIUS: "/authentication/servers/radius"
    }

    class SFOSApiError {
        +str message
        +int status_code
        +str error
        +str code
        +Any response_body
        +__init__(message: str, status_code: int, error: str, code: str, response_body: Any)
        +__str__() str
    }

    class BadRequestError
    class AuthenticationError
    class AuthorizationError
    class NotFoundError
    class ConflictError
    class UnprocessableEntityError
    class RateLimitError {
        +float retry_after
    }
    class InternalServerError
    class UnexpectedError
    class BadGatewayError
    class ServiceUnavailableError
    class GatewayTimeoutError
    class SFOSConnectionError
    class SFOSTimeoutError

    StrEnum <|-- Network
    StrEnum <|-- Firewall
    StrEnum <|-- Nat
    StrEnum <|-- Authentication

    SFOSClient ..> Network : uses
    SFOSClient ..> Firewall : uses
    SFOSClient ..> Nat : uses
    SFOSClient ..> Authentication : uses

    SFOSApiError <|-- BadRequestError
    SFOSApiError <|-- AuthenticationError
    SFOSApiError <|-- AuthorizationError
    SFOSApiError <|-- NotFoundError
    SFOSApiError <|-- ConflictError
    SFOSApiError <|-- UnprocessableEntityError
    SFOSApiError <|-- RateLimitError
    SFOSApiError <|-- InternalServerError
    SFOSApiError <|-- SFOSConnectionError
    SFOSApiError <|-- SFOSTimeoutError
    InternalServerError <|-- UnexpectedError
    InternalServerError <|-- BadGatewayError
    InternalServerError <|-- ServiceUnavailableError
    InternalServerError <|-- GatewayTimeoutError

    SFOSClient ..> SFOSApiError : raises
```

### 3.1 Structural Design & Class Taxonomy

- **Method Categorization & Functional Tiers**:
  - **Core CRUD Primitives (`get`, `post`, `patch`, `delete`)**: Handle object lifecycle state, URL parameterization, query parameter normalization, collection auto-pagination, and RFC 7396 JSON merge patching, standalone actions, and parameterized RPC actions.
  - **Dedicated Convenience Wrappers (`upload`, `move`, `test_connection`)**: Domain-specific helpers issuing multipart uploads (`upload`) and direct POST requests (`.../move`, `.../test-connection`). They provide clean, validated, and ergonomic interfaces without requiring callers to construct raw strings manually.
  - **Transport & Lifecycle (`request`, `close`)**: Provide raw HTTP access and deterministic socket lifecycle management.
- **Encapsulation of Connection State**: `SFOSClient` encapsulates the `httpx.Client` instance and maintains immutable configuration properties (`base_url`, `timeout`, `verify_ssl`).
- **Static & Class Helper Methods**:
  - `_resolve_path(endpoint, id_or_name)`: Pure function transforming domain constants and identifiers into path strings without side effects.
  - `_clean_params(params)`: Strips `None` values from parameter maps so optional parameters are not serialized as literal `"None"` in URL query strings.
  - `_error_details(response)`: Robustly parses firewall response payloads whether delivered as structured JSON or plain text.
- **Exception Class Polymorphism**: Consumers can catch high-level `SFOSApiError` to handle all client failures, or trap specific subtypes (`ConflictError`, `NotFoundError`) for granular recovery logic.

### 3.2 Invariant Guarantees & Type Safety

The class hierarchy enforces several critical runtime invariants:
1. **Type Homogeneity via `StrEnum`**: All 182 endpoint constants inherit directly from `str` and `enum.Enum`. Any function or library accepting `str` can consume an endpoint constant without explicit casting. Static type checkers (e.g. `pyright`, `mypy`) validate endpoint arguments as type-compatible with string path parameters.
2. **Immutability of Base URL & Credentials**: Once instantiated, `SFOSClient.base_url` is constructed via `f"https://{host}:{port}/api/firewall-config/v1/"`. The scheme `https` is non-negotiable; passing `http://` in `host` triggers an immediate `ValueError`, ensuring security invariants cannot be broken at runtime.
3. **Session Resource Determinism**: `SFOSClient` implements Python's Context Manager protocol (`__enter__` and `__exit__`). Upon context exit, `session.close()` is guaranteed to execute, terminating keep-alive connections and preventing file descriptor leaks in long-running services.

[↑ Back to Top](#top)

---

## 4. Use Case UML Diagram

```mermaid
graph LR
    subgraph Actors["Primary Actors"]
        Admin(("Network Admin"))
        SecEng(("SecOps Engineer"))
        CI(("CI/CD Automation"))
        Auditor(("Compliance Auditor"))
    end

    subgraph UseCases["SFOS API Client Use Cases"]
        UC1["Read Firewall Objects & Auto-Paginate Collections"]
        UC2["Filter Objects by Name / Subnet (nameContains)"]
        UC3["Provision Host & Service Definitions (Create)"]
        UC4["Modify Configurations via RFC 7396 Patch (Update)"]
        UC5["Bulk Decommission Stale Resources (Batch Delete)"]
        UC6["Reorder Firewall & NAT Rulebases (Move Top/Before/After)"]
        UC7["Execute RPC Actions (AD Group Sync / Connection Test)"]
        UC8["Inspect Security Health & DoS Telemetry"]
    end

    Admin --> UC1
    Admin --> UC3
    Admin --> UC4
    Admin --> UC6
    SecEng --> UC6
    SecEng --> UC7
    SecEng --> UC8
    CI --> UC3
    CI --> UC5
    Auditor --> UC1
    Auditor --> UC2
```

### 4.1 Actor Profiles & Operational Scenarios

- **Network Administrator**: Automates routine changes, such as spinning up new branch networks, creating zone bindings, and inserting firewall rules into production rulebases.
- **SecOps Engineer**: Manages threat feed synchronizations (`ActiveThreatResponse.THIRDPARTY_THREAT_FEEDS_BY_ID_OR_NAME_SYNCHRONIZE`), monitors DoS flood attack telemetry, and enforces TLS inspection policies.
- **CI/CD Automation Pipeline**: Runs automated testing or staging deployments, provisioning ephemeral IP address objects and tearing them down via batch deletion (`client.delete(..., items=[...])`).
- **Compliance Auditor**: Queries the firewall in a read-only capacity, auto-paginating through entire rulebases to verify compliance with organizational security benchmarks.

[↑ Back to Top](#top)

---

## 5. Sequence Diagrams

### 5.1 Client Session Lifecycle & Auto-Pagination

This sequence traces the initialization of an HTTPS session, the automatic multi-page negotiation loop, and transport teardown:

```mermaid
sequenceDiagram
    autonumber
    actor User as User Script
    participant Client as SFOSClient
    participant HTTP as httpx.Client
    participant Firewall as SFOS REST API

    User->>Client: with SFOSClient("192.168.1.1", "api-key", port=4444)
    Client->>HTTP: __init__(base_url="https://192.168.1.1:4444/api/firewall-config/v1/")
    Client-->>User: Client context entered

    User->>Client: read(Network.ZONES, pageSize=50)
    Note over Client: Determine Collection Read<br/>Compute pageTotal=True, page=1
    Client->>HTTP: GET network/zones?page=1&pageSize=50&pageTotal=true
    HTTP->>Firewall: HTTPS GET /api/firewall-config/v1/network/zones (Bearer Token)
    Firewall-->>HTTP: HTTP 200 {items: [1..50], pages: {total: 3, current: 1, size: 50}}
    HTTP-->>Client: Response (Page 1)

    loop Sequential Auto-Pagination (Page 2 to total_pages)
        Client->>HTTP: GET network/zones?page=N&pageSize=50
        HTTP->>Firewall: HTTPS GET
        Firewall-->>HTTP: HTTP 200 {items: [...]}
        HTTP-->>Client: Response (Page N)
        Client->>Client: items.extend(page["items"])
    end

    Client->>Client: Construct aggregated dict (all items, total count)
    Client-->>User: Consolidated Response {items: [1..150], pages: {total: 3, ...}}

    User->>Client: Exit 'with' context
    Client->>HTTP: close()
    HTTP-->>Client: Sockets closed and connection pool released
```

#### Detailed Sequence Mechanics:
1. **Header Injection**: On instantiation, `httpx.Client` is configured with default headers `Authorization: Bearer <api_key>` and `Accept: application/json`.
2. **First Page Fetch**: The client sends `page=1`, `pageTotal=True`, and clamps `pageSize` between `1` and `100`.
3. **Loop Termination**: The loop executes for `page_num in range(2, total_pages + 1)`. If `total_pages <= 1`, no additional HTTP requests are emitted.
4. **Metadata Preservation**: The return dictionary preserves the exact top-level schema returned by the firewall while reporting consolidated item counts.

---

### 5.2 Resource Creation & RFC 7396 Patch Update

```mermaid
sequenceDiagram
    autonumber
    actor User as User Script
    participant Client as SFOSClient
    participant HTTP as httpx.Client
    participant Firewall as SFOS REST API

    User->>Client: create(Network.ADDRESSES_IPV4, {name: "Web_SRV", ipv4Address: "10.0.1.5", type: "ipv4Address"})
    Client->>Client: _resolve_path(Network.ADDRESSES_IPV4) -> "network/addresses/ipv4"
    Client->>HTTP: POST network/addresses/ipv4 (JSON Body)
    HTTP->>Firewall: HTTPS POST /api/firewall-config/v1/network/addresses/ipv4
    Firewall-->>HTTP: HTTP 201 Created {name: "Web_SRV", ipv4Address: "10.0.1.5", ...}
    HTTP-->>Client: HTTP 201 Created
    Client-->>User: Created Object Data

    User->>Client: update(Network.ADDRESSES_IPV4, "Web_SRV", data={description: "Frontend Node"})
    Client->>Client: _resolve_path(Network.ADDRESSES_IPV4, "Web_SRV") -> "network/addresses/ipv4/Web_SRV"
    Client->>HTTP: PATCH network/addresses/ipv4/Web_SRV (Merge Patch JSON)
    HTTP->>Firewall: HTTPS PATCH /api/firewall-config/v1/network/addresses/ipv4/Web_SRV
    Firewall->>Firewall: Apply RFC 7396 merge patch to database
    Firewall-->>HTTP: HTTP 200 OK {name: "Web_SRV", description: "Frontend Node", ...}
    HTTP-->>Client: HTTP 200 OK
    Client-->>User: Decoded response (or None for an empty response)
```

#### Detailed Sequence Mechanics:
- **Creation**: Emits `POST` directly to the collection path. The firewall returns `201 Created` with the assigned system properties.
- **Merge Patch Mutation**: `patch` sends a JSON `PATCH` request to the resolved resource URI. In accordance with the API's documented RFC 7396 semantics:
  - Specified fields are updated.
  - Fields with `None` (`null` in JSON) are deleted/reverted to factory defaults.
  - Omitted fields (e.g. `ipv4Address`) remain unchanged.

---

<a id="53-rule-priority-reordering-move"></a>
<a id="53-convenience-wrapper-rule-priority-reordering-move"></a>
### 5.3 Convenience Wrapper: Rule Priority Reordering (Move)

SFOS firewall and NAT rules are evaluated in top-to-bottom order. The `move` method is a dedicated convenience wrapper that directly issues a POST request to `f"{endpoint}/move"` to atomically adjust rule sequence priority:

```mermaid
sequenceDiagram
    autonumber
    actor User as User Script
    participant Client as SFOSClient
    participant HTTP as httpx.Client
    participant Firewall as SFOS REST API

    User->>Client: move(Firewall.RULES_IPV4, {name: "rule-malware", position: "top"})
    Client->>Client: Build path: "firewall/rules/ipv4/move"
    Client->>HTTP: POST firewall/rules/ipv4/move {name: "rule-malware", position: "top"}
    HTTP->>Firewall: HTTPS POST /api/firewall-config/v1/firewall/rules/ipv4/move
    Firewall->>Firewall: Shift rule priority indexes in kernel rulebase
    Firewall-->>HTTP: HTTP 200 OK {}
    HTTP-->>Client: HTTP 200 OK
    Client-->>User: Success Response
```

#### Detailed Sequence Mechanics:
- `client.move()` directly targets the rulebase's `/move` route, eliminating manual string construction.
- Firewall, NAT, and SD-WAN `/move` routes require `name`, while `TlsInspection.RULES_IPV4` accepts either `id` or `name` (`{"id": "...", ...}` or `{"name": "...", ...}`).
- When `position` is `"top"` or `"bottom"`, the rule is moved to the respective boundary of the rulebase.
- When `position` is `"before"` or `"after"`, the caller must supply `referenceItem: {"name": "<target-name>"}` (or `{"id": "..."}` / `{"name": "..."}` for `TlsInspection.RULES_IPV4`); the engine then shifts the rule immediately adjacent to the target rule.
- A complementary convenience wrapper, `client.test_connection(endpoint, data=data, params=params)`, directly issues a POST request to `f"{endpoint}/test-connection"` for on-demand directory, SMS gateway, and threat feed connectivity verification.

---

### 5.4 Error Interception & Exception Dispatch

```mermaid
sequenceDiagram
    autonumber
    actor User as User Script
    participant Client as SFOSClient
    participant HTTP as httpx.Client
    participant Firewall as SFOS REST API

    User->>Client: read(Network.ADDRESSES_IPV4, "Missing_Host")
    Client->>HTTP: GET network/addresses/ipv4/Missing_Host
    HTTP->>Firewall: HTTPS GET /api/firewall-config/v1/network/addresses/ipv4/Missing_Host
    Firewall-->>HTTP: HTTP 404 Not Found {"error": "NotFound", "code": 4041, "message": "Host not found"}
    HTTP-->>Client: Response (status_code=404)

    Client->>Client: _raise_for_error(response)
    Client->>Client: _error_details() extracts message, error, code, response_body
    Client->>Client: Lookup status_code 404 -> NotFoundError
    Client-->>User: raise NotFoundError("Host not found", status_code=404, code=4041, ...)
```

#### Detailed Sequence Mechanics:
1. `_raise_for_error` inspects `response.is_error`. If `False`, execution continues uninterrupted.
2. If `True`, `_error_details` attempts to decode the JSON response payload.
3. If the payload contains standard SFOS error keys (`message`, `error`, `code`), they are extracted. If the response is not valid JSON, raw text is preserved.
4. The client dispatches to the corresponding typed exception subclass, attaching all extracted diagnostic attributes.

---

### 5.5 Idempotent State Reconciliation Workflow

In modern Declarative / Infrastructure-as-Code pipelines (e.g. Ansible, Terraform, GitOps), automation must be safe to run repeatedly without producing spurious errors or duplicate objects. The following sequence illustrates how `sfos-api` supports declarative reconciliation:

```mermaid
sequenceDiagram
    autonumber
    actor Orchestrator as IaC / Orchestration Engine
    participant Client as SFOSClient
    participant Firewall as SFOS REST API

    Note over Orchestrator: Target Desired State:<br/>Host: "DB_Cluster_VIP", IP: "10.0.100.50"

    Orchestrator->>Client: read(Network.ADDRESSES_IPV4, "DB_Cluster_VIP")
    Client->>Firewall: GET network/addresses/ipv4/DB_Cluster_VIP
    
    alt Object Does Not Exist
        Firewall-->>Client: HTTP 404 Not Found
        Client-->>Orchestrator: catch NotFoundError
        Note over Orchestrator: Decision: Object Missing -> CREATE
        Orchestrator->>Client: create(Network.ADDRESSES_IPV4, {name: "DB_Cluster_VIP", ipv4Address: "10.0.100.50", type: "ipv4Address"})
        Client->>Firewall: POST network/addresses/ipv4
        Firewall-->>Client: HTTP 201 Created
        Client-->>Orchestrator: Created Resource (State: CHANGED)
    else Object Exists and Matches Desired State
        Firewall-->>Client: HTTP 200 OK {name: "DB_Cluster_VIP", ipv4Address: "10.0.100.50"}
        Client-->>Orchestrator: Current State
        Note over Orchestrator: Decision: Attributes Match -> NO-OP (State: OK)
    else Object Exists but Has Drifter Attributes
        Firewall-->>Client: HTTP 200 OK {name: "DB_Cluster_VIP", ipv4Address: "10.0.100.40"}
        Client-->>Orchestrator: Current State
        Note over Orchestrator: Decision: Drift Detected -> UPDATE (RFC 7396 Patch)
        Orchestrator->>Client: update(Network.ADDRESSES_IPV4, "DB_Cluster_VIP", data={ipv4Address: "10.0.100.50"})
        Client->>Firewall: PATCH network/addresses/ipv4/DB_Cluster_VIP
        Firewall-->>Client: HTTP 200 OK
        Client-->>Orchestrator: Updated Resource (State: CHANGED)
    end
```

#### Detailed Sequence Mechanics:
1. **Deterministic Probing**: The orchestrator attempts a targeted `get()` for the resource key. Trapping `NotFoundError` cleanly bifurcates execution into a creation path versus a mutation/drift-check path.
2. **Atomic Convergence via Merge Patch**: When state drift is detected, `patch()` sends only the mutated fields using RFC 7396 merge patch semantics, avoiding destructive full-object overwrites.
3. **Zero Phantom Changes**: If active attributes match the desired state, the workflow exits cleanly with zero write I/O against the firewall's configuration database.

[↑ Back to Top](#top)

---

## 6. Activity & Workflow Diagrams

### 6.1 Read & Auto-Pagination Decision Flowchart

The `get()` method intelligently chooses between single resource retrieval, explicit single-page queries, and auto-paginated collection aggregation:

```mermaid
flowchart TD
    Start(["Start: client.get(endpoint, id_or_name, params, **kwargs)"]) --> MergeParams["Merge params dict with **kwargs into query map"]
    MergeParams --> HasId{"Is id_or_name provided and non-empty?"}

    HasId -- Yes --> CheckPaginationPaging{"Are page, pageSize, pageTotal, or fromKey in query?"}
    CheckPaginationPaging -- Yes --> RaiseError["Raise ValueError: Pagination parameters are not supported for single item"]
    CheckPaginationPaging -- No --> ResolveSinglePath["_resolve_path(endpoint, id_or_name)"]
    ResolveSinglePath --> ExecSingleGet["Execute GET Request"]
    ExecSingleGet --> ReturnSingle(["Return Single Resource Dict"])

    HasId -- No --> CheckPathVars{"Does endpoint contain template tokens like {idOrName}?"}
    CheckPathVars -- Yes --> RaiseTemplateError["Raise ValueError: Missing required id_or_name for path template"]
    CheckPathVars -- No --> CheckStrict{"Is strict_query_validation enabled?"}
    CheckStrict -- Yes --> ValidateQuery["_validate_read_query(norm_endpoint, query)"]
    ValidateQuery --> CheckExplicitPaging{"Are 'page', 'pageTotal', or 'fromKey' in query?"}
    CheckStrict -- No --> CheckExplicitPaging

    CheckExplicitPaging -- Yes --> ExecExplicitPaging["Execute single GET with caller's explicit paging params"]
    ExecExplicitPaging --> ReturnSinglePage(["Return Single Page Response (No Auto-Paging)"])

    CheckExplicitPaging -- No --> CheckNonPaginated{"Is endpoint in NON_PAGINATED or CURSOR_PAGINATED?"}
    CheckNonPaginated -- Yes --> FetchFirstRaw["Execute GET without injecting page/pageSize"]
    CheckNonPaginated -- No --> InitAutoPagination["Clamp pageSize to 1..100 (Default: 100)<br/>Inject page=1, pageTotal=True"]
    InitAutoPagination --> FetchFirstPage["Execute GET for Page 1"]
    FetchFirstRaw --> HasItemsList{"Is response a dict with 'items' list?"}
    FetchFirstPage --> HasItemsList

    HasItemsList -- No --> ReturnRaw(["Return Raw Response"])
    HasItemsList -- Yes --> HasCursor{"Does response have pages.nextKey?"}
    HasCursor -- Yes --> CursorLoop["Follow cursor pages via _read_cursor_pages(fromKey=nextKey)"]
    CursorLoop --> ReturnAggregated(["Return Consolidated Result"])
    HasCursor -- No --> InitList["Initialize items = list(first['items'])<br/>Extract total_pages from first['pages']['total']"]

    InitList --> LoopCond{"page_num <= total_pages?"}
    LoopCond -- Yes --> FetchNextPage["Execute GET for Page N"]
    FetchNextPage --> AppendItems["items.extend(page['items'])"]
    AppendItems --> NextPage["page_num = page_num + 1"]
    NextPage --> LoopCond

    LoopCond -- No --> BuildConsolidated["Construct consolidated response dict<br/>pages.current = 1, pages.size = len(items), pages.total = total_pages"]
    BuildConsolidated --> ReturnAggregated(["Return Consolidated Result"])
```

---

### 6.2 Path Parameter Resolution Algorithm

The `_resolve_path` method is a deterministic routing algorithm handling both standard collection paths and OpenAPI path templates:

```mermaid
flowchart TD
    In(["Input: endpoint, id_or_name"]) --> FindPlaceholders["placeholders = _PLACEHOLDER_RE.findall(endpoint)"]
    FindPlaceholders --> CheckMulti{"len(placeholders) > 1?"}
    CheckMulti -- Yes --> RaiseMulti["Raise ValueError: Multiple path parameters not supported"]
    CheckMulti -- No --> HasId{"id_or_name is not None?"}

    HasId -- Yes --> QuoteVal["quoted = urllib.parse.quote(str(id_or_name), safe='')"]
    QuoteVal --> HasTemplateInEndpoint{"placeholders non-empty?"}
    HasTemplateInEndpoint -- Yes --> ReplaceTemplate["Substitute first token with quoted identifier<br/>_PLACEHOLDER_RE.sub(lambda _: quoted, endpoint, count=1)"]
    ReplaceTemplate --> OutPath(["Return Resolved Path String"])

    HasTemplateInEndpoint -- No --> AppendSlash["Append quoted identifier to base path<br/>f'{endpoint.rstrip('/')}/{quoted}'"]
    AppendSlash --> OutPath

    HasId -- No --> CheckDanglingTemplate{"placeholders non-empty?"}
    CheckDanglingTemplate -- Yes --> RaiseMissingParam["Raise ValueError: Endpoint requires id_or_name"]
    CheckDanglingTemplate -- No --> ReturnBase["Return endpoint string unmodified"]
    ReturnBase --> OutPath
```

---

### 6.3 Error Handling & Response Parsing Pipeline

```mermaid
flowchart LR
    HTTPResp["HTTP Response from Firewall"] --> CheckStatus{"Is response.is_error?"}
    CheckStatus -- False --> Check204{"Status == 204 or empty content?"}
    Check204 -- Yes --> RetNone["Return None"]
    Check204 -- No --> CheckJSON{"Content-Type contains JSON?"}
    CheckJSON -- Yes --> RetJSON["Return response.json()"]
    CheckJSON -- No --> RetText["Return response.text"]

    CheckStatus -- True --> ExtractBody["Extract JSON body or fallback to text"]
    ExtractBody --> ParseDetails["Extract 'message', 'error', 'code' fields"]
    ParseDetails --> MatchCode{"Match HTTP Status Code"}

    MatchCode -- 400 --> Exc400["BadRequestError"]
    MatchCode -- 401 --> Exc401["AuthenticationError"]
    MatchCode -- 403 --> Exc403["AuthorizationError"]
    MatchCode -- 404 --> Exc404["NotFoundError"]
    MatchCode -- 409 --> Exc409["ConflictError"]
    MatchCode -- 422 --> Exc422["UnprocessableEntityError"]
    MatchCode -- 429 --> Exc429["RateLimitError"]
    MatchCode -- 500 --> Exc500["InternalServerError"]
    MatchCode -- 502 --> Exc502["BadGatewayError"]
    MatchCode -- 503 --> Exc503["ServiceUnavailableError"]
    MatchCode -- 504 --> Exc504["GatewayTimeoutError"]
    MatchCode -- "Other >= 500" --> Exc500
    MatchCode -- "Other 4xx" --> ExcBase["SFOSApiError"]

    Exc400 --> RaiseExc["Raise Concrete SFOSApiError Subclass"]
    Exc401 --> RaiseExc
    Exc403 --> RaiseExc
    Exc404 --> RaiseExc
    Exc409 --> RaiseExc
    Exc422 --> RaiseExc
    Exc429 --> RaiseExc
    Exc500 --> RaiseExc
    Exc502 --> RaiseExc
    Exc503 --> RaiseExc
    Exc504 --> RaiseExc
    ExcBase --> RaiseExc
```

[↑ Back to Top](#top)

---

## 7. State Transition Diagram

```mermaid
stateDiagram-v2
    [*] --> Uninitialized: Python Process Start

    Uninitialized --> Initialized: SFOSClient(host, api_key, port, verify, timeout)
    note right of Initialized
        - Validate host format (no scheme)
        - Validate non-empty credentials
        - Instantiate httpx.Client connection pool
        - Set default Bearer authorization headers
    end note

    Initialized --> ActiveSession: with client / direct method call
    
    state ActiveSession {
        [*] --> Idle: Ready for operations

        Idle --> Reading: client.get()
        Reading --> Paginating: Auto-pagination loop
        Paginating --> Paginating: Fetch page N
        Paginating --> Idle: Aggregation finished
        Reading --> Idle: Single resource returned

        Idle --> Creating: client.post()
        Creating --> Idle: 201 Created

        Idle --> Updating: client.patch()
        Updating --> Idle: 200 OK (RFC 7396 Patch)

        Idle --> Deleting: client.delete()
        Deleting --> Idle: 200/204 Deleted

        Idle --> ConvenienceWrapper: client.upload() / client.move() / client.test_connection()
        ConvenienceWrapper --> Idle: Wrapper execution complete

        Idle --> ErrorState: HTTP 4xx / 5xx encountered
        ErrorState --> Idle: Caught and handled by caller
    }

    ActiveSession --> Closed: client.close() or context exit
    Closed --> [*]: Sockets terminated, connection pool drained
```

### 7.1 Client Lifecycle States & Transitions

- **`Uninitialized` ➔ `Initialized`**: Validates configuration parameters. If `host` contains a scheme (`https://`), or if `host` or `api_key` are empty strings, instantiation fails immediately with `ValueError`.
- **`ActiveSession`**: The client enters a reusable state. The internal `httpx.Client` maintains an HTTP/1.1 persistent keep-alive pool. Multiple requests reuse existing TCP/TLS handshakes, dramatically improving performance for multi-step automations.
- **`Closed`**: Disposes of internal sockets and releases all transport resources. Calling `client.close()` or exiting a `with` block guarantees zero resource leaks.

[↑ Back to Top](#top)

---

## 8. Deployment & Network Topologies

```mermaid
graph TD
    subgraph Management_Zone["Secure Administrative Network"]
        DevOpsMachine["DevOps Workstation<br/>(Python 3.11+, Jupyter, CLI Scripts)"]
        AutomationServer["Automation Orchestrator<br/>(Ansible Controller, Terraform, CI/CD Runner)"]
        SIEM["Monitoring & Compliance Collector<br/>(Audit Scripts, Telemetry Scrapers)"]
    end

    subgraph Perimeter_Zone["Sophos Firewall OS (SFOS) Security Appliance"]
        WebAdminEngine["WebAdmin REST API Gateway<br/>(HTTPS Port 4444 / nginx reverse proxy)"]
        AuthModule["SFOS Authentication Subsystem<br/>(API Key Verification / RBAC Permissions)"]
        ConfigEngine["Configuration Engine<br/>(Validation & Configuration Store)"]
        KernelRulebase["Packet Filtering & NAT Engine<br/>(Kernel Stateful Rulebase)"]
    end

    DevOpsMachine -->|TLS 1.2+ / Port 4444 / Bearer Token| WebAdminEngine
    AutomationServer -->|TLS 1.2+ / Port 4444 / Bearer Token| WebAdminEngine
    SIEM -->|TLS 1.2+ / Port 4444 / Bearer Token| WebAdminEngine

    WebAdminEngine --> AuthModule
    AuthModule --> ConfigEngine
    ConfigEngine --> KernelRulebase
```

### 8.1 Firewall Communication Architecture

- **Port & Protocol**: SFOS REST API operations are served over HTTPS on the WebAdmin management port (default: `4444`, configurable via `Administration > Admin and user settings`).
- **Authentication**: Uses HTTP Bearer tokens. API keys are generated under `Administration > API` in the WebAdmin UI and mapped to firewall administrator profiles with granular Role-Based Access Control (RBAC).
- **Mutual TLS & CA Trust**: Supports standard commercial certificates, enterprise internal PKI CA bundles, or disabled validation (`verify_ssl=False`) for isolated lab deployments.

### 8.2 High Availability (HA) Cluster Topology

Sophos Firewall OS appliances are frequently deployed in High Availability (Active-Passive or Active-Active) clusters to guarantee zero-downtime perimeter security:

```mermaid
graph TB
    subgraph Management_Network["Management Subnet / DevOps Orchestration"]
        OrchestratorNode["sfos-api Client Orchestrator"]
    end

    subgraph Cluster_Boundary["Sophos Firewall HA Cluster Pair"]
        SharedInterface["Shared Interface IP with Virtual MAC (VMAC)<br/>(e.g. 192.168.1.1:4444 / VMAC)"]

        subgraph Primary_Node["Primary / Active Appliance (Node A)"]
            NodeA_Engine["WebAdmin REST API Gateway (Active Read/Write)"]
            NodeA_DB[("Configuration Store (Primary)")]
        end

        subgraph Auxiliary_Node["Auxiliary / Standby Appliance (Node B)"]
            PeerAdminIP["Peer Administration IP (Dedicated Aux Mgmt Port)"]
            NodeB_Engine["WebAdmin REST API (Passive / Read-Only)"]
            NodeB_DB[("Configuration Store (Standby Replica)")]
        end

        DedicatedLink["Dedicated HA Interconnect & Heartbeat Link (e.g. Port D)"]
    end

    OrchestratorNode -->|"HTTPS Port 4444 (Target Shared IP / VMAC)"| SharedInterface
    SharedInterface --> NodeA_Engine
    NodeA_Engine --> NodeA_DB
    NodeA_DB ==>|"Real-time DB Sync & Config Mirroring"| DedicatedLink
    DedicatedLink ==> NodeB_DB
    NodeB_DB -.-> NodeB_Engine

    OrchestratorNode -.->|"Direct Diagnostic Check (Peer Port)"| PeerAdminIP
    PeerAdminIP -.-> NodeB_Engine
```

#### HA Operational Mechanics for `sfos-api`:
1. **Virtual MAC (VMAC) Continuity**: Sophos Firewall HA utilizes Virtual MAC (VMAC) address mode for cluster interfaces. Both appliances share the identical IP address on monitored interfaces bound to a cluster Virtual MAC. In the event of a primary node failover, the auxiliary appliance seamlessly takes ownership of the Virtual MAC and interface IP. Because the MAC address remains unchanged, connected switches and orchestration hosts do not require ARP table updates or IP re-addressing.
2. **Replication Transparency**: Changes provisioned to the active Primary node via `sfos-api` (such as firewall rules, IP host objects, and NAT policies) are committed to the primary configuration store and replicated to the auxiliary node across the dedicated HA interconnect link.
3. **Peer Administration Port for Diagnostics**: For dedicated out-of-band diagnostics, administrators can configure a Peer Administration IP on an unmonitored auxiliary port to access the passive node directly.
4. **Configuration API Scope**: The Sophos Firewall Configuration REST API (`/api/firewall-config/v1/`) manages firewall configuration resources; cluster state telemetry, failover events, and heartbeat health are monitored out-of-band via SNMP, Syslog destinations (`Logging.LOG_DESTINATIONS_SYSLOG_SERVERS`), or Sophos Fusion.

[↑ Back to Top](#top)

---

## 9. Security Architecture & Threat Model

### 9.1 Threat Mitigation Strategies

| Threat Vector | Severity | Mitigation in `sfos-api` |
|---|:---:|---|
| **Credential Interception** | Critical | Strict HTTPS enforcement; client refuses to instantiate if an unencrypted HTTP URL is supplied. |
| **Path Traversal / URL Injection** | High | All resource identifiers in `_resolve_path` are sanitized using `urllib.parse.quote(id_or_name, safe="")`, preventing path injection attacks (`../`). |
| **Credential Leakage in Logs** | Medium | The client does not log sensitive headers; API tokens are isolated in HTTP session headers and are never included in exception messages or `__str__` outputs. |
| **Unbounded Pagination Denial of Service** | Medium | `pageSize` is clamped to SFOS limits (`1` to `100`), preventing memory exhaustion on client and server. |

### 9.2 Certificate Verification Configurations

```python
# Mode 1: Strict Verification with Custom Internal CA (Recommended for Enterprise)
client = SFOSClient("fw.corp.local", "token", verify_ssl="/etc/ssl/certs/corp-root-ca.pem")

# Mode 2: Standard Public CA Verification
client = SFOSClient("fw.domain.com", "token", verify_ssl=True)

# Mode 3: Lab / Development Mode (Bypasses Self-Signed Certificate Warnings)
client = SFOSClient("192.168.1.1", "token", verify_ssl=False)
```

### 9.3 STRIDE Threat Analysis Matrix

A comprehensive STRIDE threat modeling assessment was performed on the client-to-appliance interaction:

| STRIDE Category | Threat Description | Architectural Countermeasure in `sfos-api` |
|---|---|---|
| **Spoofing** | Attacker impersonates the SFOS WebAdmin gateway using a rogue certificate or DNS poisoning. | By default, `verify_ssl=True` enforces TLS certificate chain verification against trusted CAs. Passing an enterprise CA path verifies internal PKI signatures. |
| **Tampering** | In-transit modification of firewall policy payloads (e.g. altering source IP or port definitions). | Strict TLS 1.2+ encryption prevents wire-level packet alteration. All payloads are signed and hashed by the TLS session keys negotiated during the handshake. |
| **Repudiation** | Administrator denies initiating a rulebase deletion or policy alteration. | Every API call carries the Bearer token associated with a named SFOS Administrator Profile. SFOS logs all REST mutations to `/log/syslog.log` and the WebAdmin Audit Log with the associated administrator username. |
| **Information Disclosure** | Exposure of sensitive network topology or administrative credentials in stack traces. | `SFOSApiError` custom string representation (`__str__`) sanitizes headers, outputting only the HTTP status code, API error message, and response body, guaranteeing that Bearer tokens are never leaked to log files or consoles. |
| **Denial of Service** | Excessive pagination requests consuming all firewall worker threads or exhausting client heap space. | `pageSize` is clamped to SFOS specification bounds (1–100). The auto-pagination engine executes sequentially, preventing connection exhaustion on the appliance's Nginx reverse proxy. |
| **Elevation of Privilege** | An API token with read-only rights attempts to execute mutative writes (e.g. creating rules). | The client dispatches HTTP 403 responses to `AuthorizationError`. SFOS enforces Role-Based Access Control (RBAC) at the gateway daemon, preventing privilege escalation. |

### 9.4 Enterprise Secrets Management & Key Storage

Hardcoding API tokens in scripts violates enterprise security baselines. Production deployments should resolve credentials through external secret stores:

```python
from sfos_api import SFOSClient, Firewall

# Pattern A: INI Profile Configuration
with SFOSClient(config_path=".credentials/config.ini", profile="firewall") as client:
    rules = client.get(Firewall.RULES_IPV4)

# Pattern B: Explicit Credentials from External Secret Store
with SFOSClient("192.168.1.1", api_key_from_vault, verify_ssl=True) as client:
    rules = client.get(Firewall.RULES_IPV4)
```

[↑ Back to Top](#top)

---

## 10. Concurrency, Performance & Resource Management

### 10.1 Concurrency Model & Thread Safety

- **Thread-Safe Transport**: `SFOSClient` wraps `httpx.Client`, which is thread-safe. A single `SFOSClient` instance can be shared across worker threads in multi-threaded applications (e.g. concurrent auditing across different endpoints).
- **Synchronous Design Rationale**: Network firewalls serialize configuration updates internally to prevent race conditions in the packet filtering kernel. Asynchronous parallel writes to the same rulebase frequently result in `409 Conflict` errors from the firewall engine. A synchronous client model naturally aligns with the firewall's serialized transaction model.

### 10.2 Memory Footprint & Socket Optimization

- **Zero-Copy Endpoint References**: Endpoints are interned strings in the Python interpreter. Storing 182 endpoint constants consumes less than 15 KB of memory.
- **Connection Keep-Alive**: Reuses underlying TCP connections across requests, eliminating the overhead of repeated TLS handshakes during large multi-page queries or bulk provisioning runs.

### 10.3 Connection Pool Management & Socket Tuning

The internal `httpx.Client` manages an HTTP/1.1 connection pool configured for high-throughput firewall administration:
- **Connection Persistence**: Active sockets are maintained in a keep-alive pool. Subsequent requests to the same firewall reuse the open socket, saving 150–300ms per call by skipping TCP 3-way handshake and TLS cipher negotiation.
- **Socket Timeouts**: Configurable per-client via `timeout` (default `30.0` seconds). Long-running operations (such as firmware backup creation or Active Directory synchronization) may require higher timeouts (e.g. `timeout=60.0`).
- **Deterministic Teardown**: Implementing the context manager protocol (`with SFOSClient(...) as client:`) ensures that `session.close()` executes even in the event of unhandled exceptions, closing lingering sockets and preventing resource leaks.

[↑ Back to Top](#top)

---

## 11. Extensibility & Integration Patterns

### 11.1 Low-Level Escape Hatch (`client.request`)

For newly released SFOS endpoints or custom undocumented RPC paths not yet covered in `endpoints.py`, `client.request()` provides a low-level invocation mechanism while retaining authentication, error translation, and base URL routing:

```python
# Forward-compatible execution of unmodeled endpoint
custom_data = client.request(
    "POST",
    "/custom/experimental-endpoint",
    json_data={"featureFlag": True},
)
```

### 11.2 Infrastructure-as-Code (IaC) Integration

`sfos-api` is designed for embedding into custom automation engines:
- **Ansible Modules**: Can be imported into custom Ansible library modules to provision firewall objects idempotently using `get()` checks followed by `post()` or `patch()`.
- **Terraform Custom Providers**: Provides clean Python bindings for Terraform provider sidecars or Pulumi dynamic providers.
- **Continuous Compliance Scrapers**: Facilitates automated drift detection by comparing active firewall states against Git-managed YAML/JSON desired-state declarations.

### 11.3 Idempotent Desired-State Loop Pattern

Below is an enterprise implementation pattern for an idempotent resource reconciler:

```python
from sfos_api import SFOSClient, Network
from sfos_api.exceptions import NotFoundError, SFOSApiError


def reconcile_ip_host(client: SFOSClient, name: str, ip: str, description: str = "") -> dict:
    """Idempotently ensures an IPv4 host object exists with the desired attributes."""
    try:
        current = client.get(Network.ADDRESSES_IPV4, name)
        # Object exists; check if drift occurred
        if current.get("ipv4Address") != ip or current.get("description") != description:
            print(f"[DRIFT DETECTED] Updating {name}...")
            return client.patch(
                Network.ADDRESSES_IPV4,
                name,
                data={
                    "ipv4Address": ip,
                    "description": description,
                },
            )
        print(f"[IN SYNC] {name} already matches desired state.")
        return current
    except NotFoundError:
        # Object does not exist; create it
        print(f"[MISSING] Creating host object {name}...")
        return client.post(
            Network.ADDRESSES_IPV4,
            {
                "name": name,
                "ipv4Address": ip,
                "type": "ipv4Address",
                "description": description,
            },
        )
```

### 11.4 Observability, Auditing & Event Hook Interception

`sfos-api` can be augmented with audit logging and distributed tracing by tapping into `httpx` event hooks:

```python
import logging
import httpx
from sfos_api import SFOSClient, Firewall

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sfos.audit")


def log_request(request: httpx.Request):
    logger.info("AUDIT OUT -> %s %s", request.method, request.url)


def log_response(response: httpx.Response):
    logger.info(
        "AUDIT IN  <- %s (Status: %d in %.2fs)",
        response.request.url,
        response.status_code,
        response.elapsed.total_seconds(),
    )


# Inject hooks directly into client session
with SFOSClient("192.168.1.1", "api-token", verify_ssl=False) as client:
    client.session.event_hooks["request"].append(log_request)
    client.session.event_hooks["response"].append(log_response)

    rules = client.get(Firewall.RULES_IPV4)
```

[↑ Back to Top](#top)

---

## 12. Domain Taxonomy & Functional Subsystem Matrix

The 27 domain `StrEnum` classes in `sfos_api.endpoints` are organized into 6 logical architectural categories reflecting the operational model of Sophos Firewall OS:

| Category | Domain Classes | Key Endpoints & Capabilities |
|---|---|---|
| **1. Security, Policies & Inspection** | `AclExceptionRules`, `DenialOfService`, `Firewall`, `IntrusionPrevention`, `Nat`, `TlsInspection` | IPv4/IPv6 firewall rules, NAT translation rules, ACL bypass exceptions, DoS attack rate limiting, IPS policies & custom signatures, TLS inspection & decryption profiles. |
| **2. Network, Routing & Infrastructure** | `Network`, `Routing`, `SdWan`, `TrafficShaping`, `Wireless`, `SpoofProtection` | Host/network/range/MAC/FQDN address objects, network zones, interfaces, static unicast/multicast routes, WAN gateways, SD-WAN policy routes, bandwidth throttling, wireless protection & APs, IP spoof filtering. |
| **3. Identity, Authentication & Certificates** | `Authentication`, `Certificate` | Network/admin users, user groups, Active Directory, LDAP, RADIUS, TACACS, Generic IdP SSO, MFA/TOTP settings, captive portal, X.509 CAs, certificates, CSRs, CRLs. |
| **4. VPN & Remote Connectivity** | `IpsecVpn`, `SslVpn` | IPsec site-to-site & remote access tunnels, failover groups, connection profiles, SSL VPN server/client configurations, and remote access policies. |
| **5. Threat Protection & Content Security** | `ActiveThreatResponse`, `Application`, `MalwareProtection`, `Waf`, `Web`, `ZeroDayProtection` | Sophos X-Ops and 3rd-party threat intelligence feeds, application filter objects & categories, web URL groups, content filters & bypass exceptions, WAF protection & authentication policies, zero-day analysis settings. |
| **6. System, Administration & Observability** | `Administration`, `Logging`, `Monitoring`, `Notification`, `System` | Administrator profiles, access permissions, API configuration, system messages, schedules, Syslog server log export, SNMP settings, email notification alerts, backup settings, and hotfix, pattern & security updates. |

---

[↑ Back to Top](#top)

# Firewall API - Sophos Firewall OS REST API Client

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Development Status: Beta 0.8.0](https://img.shields.io/badge/Status-Beta%200.8.0-orange.svg)](https://pypi.org/project/sfos-api/)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

A  Python 3.11+ client for Sophos Firewall OS (SFOS) REST API using domain-grouped `StrEnum` classes.

**Beta 0.8.0 API:** Endpoint definitions and documentation are checked against the bundled `Sophos Firewall Configuration OpenAPI specification` (corresponding to the official [Sophos Firewall API Reference](https://docs.sophos.com/nsg/sfos-api/rest-api/index.html)). Its metadata lists [Sophos Firewall APIs](https://developer.sophos.com) as the contact and identifies the document as OpenAPI 3.0.0 and API version 1.0.0. This repository does not record the upstream revision or retrieval date, so the file should not be assumed to be the latest release. Available operations may vary by firewall firmware.

---

## 🌟 Key Architecture & Features

`sfos_api` offers a lightweight architecture designed for developers who want IDE auto-completion and type safety without the overhead of heavy metadata classes.

| Feature | Firewall API (`sfos-api`) |
|---|---|
| **Architecture** | **Domain `StrEnum` classes** |
| **Endpoint Registry** | **27 Domain Classes** (`Network.*`, `Firewall.*`, `Nat.*`, etc.) |
| **Endpoint Types** | **Native `str` singletons via `StrEnum`** |
| **Runtime Overhead** | **Zero runtime overhead (strings)** |
| **IDE Autocomplete** | **Organized by domain: type `Firewall.` or `Network.`** |
| **JSON Serialization** | **Directly serializable as `str`** |
| **Core CRUD & Actions** | **`post` (resources & actions), `get`, `patch`, `delete`** |
| **Convenience Wrappers** | **`move` (rule priority), `test_connection` (service diagnostics)** |
| **Low-Level & Lifecycle** | **`request` (custom HTTP), `close` (session teardown)** |
| **Auto-Pagination** | **Transparent multi-page fetch** |


---

## 📦 Installation

```bash
pip install sfos-api
```

Or install in editable mode for local development:

```bash
git clone https://github.com/Mitko-n/sfos_api.git
cd sfos_api
pip install -e .
```

---

## 🚀 Quick Start

```python
from sfos_api import SFOSClient, Network, Firewall, Nat, Authentication

# Initialize client
with SFOSClient("192.168.1.1", "your-api-key") as client:
    # --- 1. Core CRUD Operations ---
    # Read zones (auto-paginated)
    zones = client.get(Network.ZONES)
    print(f"Total zones: {len(zones['items'])}")

    # Read firewall rules (custom page size)
    rules = client.get(Firewall.RULES_IPV4, pageSize=25)

    # Create a new host
    client.post(
        Network.ADDRESSES_IPV4,
        {"name": "Branch_Router", "ipv4Address": "10.200.1.1", "type": "ipv4Address"},
    )

    # Update host description (RFC 7396 JSON Merge Patch)
    client.patch(Network.ADDRESSES_IPV4, "Branch_Router", data={"description": "Primary edge gateway"})

    # --- 2. Convenience Wrappers (Rule Reordering & Service Testing) ---
    # Move a firewall rule to the top of the rulebase
    client.move(Firewall.RULES_IPV4, {"name": "Allow_Outbound", "position": "top"})

    # Test LDAP server connectivity and credentials
    client.test_connection(
        Authentication.SERVERS_LDAP,
        data={
            "name": "Corporate_LDAP",
            "serverAddress": {"ipv4Address": "10.0.10.5"},
            "version": "3",
            "connectionSecurity": "none",
            "port": 389,
            "anonymousLogin": True,
            "authenticationAttribute": "uid",
            "userMapping": {"displayName": "displayName", "email": "mail"},
            "baseDN": "OU=Users,DC=example,DC=com",
        },
    )

    # --- 3. Resource Cleanup (Delete) ---
    client.delete(Network.ADDRESSES_IPV4, "Branch_Router")
```

---

## 📚 Domain StrEnum Organization

All 182 endpoint constants are grouped into 27 domain classes:

| Domain Class | Description | Example Endpoints |
|---|---|---|
| `Network` | Interfaces, IP addresses, zones, DNS, DHCP | `Network.ZONES`, `Network.ADDRESSES_IPV4`, `Network.INTERFACES_NETWORK_INTERFACES` |
| `Firewall` | IPv4 & IPv6 firewall rules and policy ordering | `Firewall.RULES_IPV4`, `Firewall.RULES_IPV6` |
| `Nat` | Source and destination NAT rules | `Nat.RULES_IPV4`, `Nat.RULES_IPV6` |
| `Authentication` | Users, groups, AD, LDAP, RADIUS, MFA | `Authentication.SERVERS_ACTIVE_DIRECTORY`, `Authentication.SERVERS_LDAP` |
| `Routing` | Static unicast/multicast routes, WAN gateways | `Routing.STATIC_UNICAST_ROUTES_IPV4`, `Routing.GATEWAYS_WAN_IPV4` |
| `SdWan` | Policy-based SD-WAN routing paths | `SdWan.ROUTES_IPV4`, `SdWan.ROUTES_IPV6` |
| `TlsInspection` | SSL/TLS decryption and inspection rules | `TlsInspection.RULES_IPV4`, `TlsInspection.DECRYPTION_PROFILES` |
| `System` | Backups, firmware, hotfixes, pattern updates | `System.BACKUP_SETTINGS`, `System.SECURITY_UPDATES` |
| ... and other domains | IPS, WAF, Wireless, VPN, DoS, Malware | See [Endpoints Reference](./docs/endpoints_reference.md) |

---

## 📖 Documentation Index

- [**API Reference**](./docs/api_reference.md) — Comprehensive technical reference: core CRUD methods (`get`, `post`, `patch`, `delete`), dedicated convenience wrappers (`upload`, `move`, `test_connection`), low-level transport (`request`, `close`), and the exception hierarchy.

- [**Endpoints Reference**](./docs/endpoints_reference.md) — Complete catalog of all 27 domains and 182 endpoint constants.
- [**Architecture & UML Specification**](./docs/architecture.md) — System architecture, Class, Use Case, Sequence, Activity, and State UML diagrams with Mermaid.
- [**Examples**](./examples/README.md) — Setup, safety notes, and OpenAPI cross-references for the sample scripts and notebooks.

---

## 🧪 Running Tests & Code Quality

```bash
# Run unit tests
pytest tests/ -v

# Lint & format check with Ruff
ruff check .
ruff format --check .
```

---

## 📄 License & Legal Notice

This project (`src/sfos_api/`, `tests/`, `examples/`, `scripts/`, `README.md`, and `docs/`) is licensed under the MIT License — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE) for full details.

- **Third-Party API Specification**: `docs/.sophos_firewall_api_docs/firewall_config_openapi.yaml` is Sophos documentation from the [Sophos Firewall API Reference](https://docs.sophos.com/nsg/sfos-api/rest-api/index.html) and remains the property of **Sophos Ltd.** It is not covered by the repository's MIT License and is excluded from built Python wheels.
- **Trademarks & Non-Affiliation**: `sfos-api` is an independent, unofficial client library and is not affiliated with, endorsed by, or supported by Sophos Ltd. *Sophos* and *Sophos Firewall* are trademarks of Sophos Ltd.

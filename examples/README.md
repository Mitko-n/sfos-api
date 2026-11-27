# Firewall API - Interactive Examples & Notebooks

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)
[![Development Status: Beta 0.8.0](https://img.shields.io/badge/Status-Beta%200.8.0-orange.svg)](https://pypi.org/project/sfos-api/)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Executable Jupyter notebook examples and standalone Python scripts demonstrating the `sfos-api` client against Sophos Firewall OS (SFOS).

These Beta 0.8.0 examples use endpoint constants checked against the bundled `Sophos Firewall Configuration OpenAPI specification`. Its metadata lists [Sophos Firewall APIs](https://developer.sophos.com) as the contact and identifies the document as OpenAPI 3.0.0 and API version 1.0.0. This repository does not record the upstream revision or retrieval date, so the file should not be assumed to be the latest release. The operations supported by an appliance may vary by firmware version.

The [Endpoints Reference](../docs/endpoints_reference.md) maps each endpoint constant to its API path and supported methods. The examples demonstrate client behavior on top of those operations: for example, `get()` may paginate automatically and `delete()` may aggregate results across batches. These client conveniences are not additional OpenAPI operations.

> [!WARNING]
> The notebooks and quickstart make real changes when run against a firewall, including creating and deleting objects, moving rules, and testing connectivity. Use a disposable or test appliance and review each cell before execution.

---

## 📁 Directory Organization

| File / Script | Description |
|---|---|
| [**`administration.ipynb`**](./administration.ipynb) | Administration resources (schedules, access profiles, permissions, API & system settings) |
| [**`ipv4_addresses.ipynb`**](./ipv4_addresses.ipynb) | IPv4 address CRUD operations using Domain StrEnum objects |
| [**`fqdns.ipynb`**](./fqdns.ipynb) | FQDN host definitions, wildcards, and domain queries |
| [**`ipv4_address_groups.ipynb`**](./ipv4_address_groups.ipynb) | Address groups and member management |
| [**`interfaces.ipynb`**](./interfaces.ipynb) | Network interface CRUD operations, filtering, and pagination |
| [**`zones.ipynb`**](./zones.ipynb) | Network zones (LAN, DMZ, WAN) creation and management |
| [**`services.ipynb`**](./services.ipynb) | TCP, UDP, ICMP custom services and port specifications |
| [**`service_groups.ipynb`**](./service_groups.ipynb) | Service group operations and membership |
| [**`ipv4_firewall_rules.ipynb`**](./ipv4_firewall_rules.ipynb) | Firewall rule creation, priority ordering, and logging |
| [**`ipv4_nat_rules.ipynb`**](./ipv4_nat_rules.ipynb) | IPv4 SNAT/DNAT rules, masquerading, and priority ordering (`client.move`) |
| [**`nested_parameterized_resources.ipynb`**](./nested_parameterized_resources.ipynb) | In-path substitution examples (syslog logs, AD groups, threat feeds, DoS) |
| [**`web.ipynb`**](./web.ipynb) | Web filtering (URL groups, categories, content filters, exceptions, policies & scan settings) |
| [**`quickstart.py`**](./quickstart.py) | Standalone Python script for end-to-end CRUD lifecycle |

---

## 🚀 Quick Setup & Prerequisites

### 1. INI Configuration (`.credentials/config.ini`)

Copy the example configuration at the workspace root into `.credentials/config.ini`:

```bash
cp ../.credentials/config.ini.example ../.credentials/config.ini
```

Edit `.credentials/config.ini` and populate the `[firewall]` section (or add additional named profiles such as `[firewall_hq]`):

```ini
[firewall]
host = 192.168.1.1                  # Firewall IP or hostname (no https:// prefix)
api_key = your_api_key_here         # API Key with appropriate admin privileges
port = 4444                         # WebAdmin / API Port (default: 4444)
verify_ssl = false                  # Set true or a CA bundle path in production
timeout = 30.0                      # HTTP timeout in seconds
# ad_password =                     # Optional; required only for the AD connection-test step in quickstart.py
```

For a self-signed certificate, set `verify_ssl = false` only when you understand the risk. Do not commit `.credentials/config.ini` or put real credentials in notebooks, scripts, or source control. The supplied `config.ini.example` contains placeholders only.

### 2. Install Editable Package & Jupyter

```bash
# Install sfos-api in editable mode from workspace root
pip install -e ".[examples]"

# Install Jupyter notebook dependencies
pip install jupyter ipython
```

### 3. Launch Notebooks

You can run the notebooks directly inside **VS Code / Cursor** with the Jupyter extension, or launch the classic Jupyter server:

```bash
# Launch notebooks:
jupyter notebook examples/

# Or run the standalone script:
python examples/quickstart.py
```

---

## 📚 Example Notebooks

The quickstart's main wire operations map to these OpenAPI paths and methods:

| Quickstart operation | OpenAPI path | Method |
|---|---|---|
| Read zones | `/network/zones` | `GET` |
| Create / read / update / delete an IPv4 address | `/network/addresses/ipv4` and `/network/addresses/ipv4/{idOrName}` | `POST`, `GET`, `PATCH`, `DELETE` |
| Create / read / batch-delete two IPv4 firewall rules | `/firewall/rules/ipv4` and `/firewall/rules/ipv4/delete` | `POST`, `GET` |
| Exchange firewall rule positions | `/firewall/rules/ipv4/move` | `POST` |
| Test an Active Directory connection | `/authentication/servers/active-directory/test-connection` | `POST` |

`SpoofProtection.TRUSTED_MACS_IMPORT` requires `multipart/form-data`. The client supports this operation through `client.upload()` or multipart arguments to `client.post()`; the current notebooks do not include a file-upload example. See the [API reference](../docs/api_reference.md#6b-upload).

For notebook-specific resource paths and methods, use the linked endpoint constants in each notebook and the Endpoints Reference crosswalk.

| Notebook | Domain | Key Operations Covered |
|---|---|---|
| [`administration.ipynb`](./administration.ipynb) | `Administration` | Schedules (recurring & one-time), access profiles, permissions, system/API/portal settings |
| [`ipv4_addresses.ipynb`](./ipv4_addresses.ipynb) | `Network` | Single IP, ranges, subnets, lists, auto-pagination, filters |
| [`fqdns.ipynb`](./fqdns.ipynb) | `Network` | FQDN host definitions, wildcards, domain queries |
| [`ipv4_address_groups.ipynb`](./ipv4_address_groups.ipynb) | `Network` | Creating and updating address group members |
| [`interfaces.ipynb`](./interfaces.ipynb) | `Network` | VLAN interface creation, reading, updating, deleting, filtering |
| [`zones.ipynb`](./zones.ipynb) | `Network` | Creating, updating, and querying network zones (LAN, DMZ, WAN) |
| [`services.ipynb`](./services.ipynb) | `Network` | TCP, UDP, ICMP custom services and port specifications |
| [`service_groups.ipynb`](./service_groups.ipynb) | `Network` | Grouping multiple network services |
| [`ipv4_firewall_rules.ipynb`](./ipv4_firewall_rules.ipynb) | `Firewall` | Creating accept/drop rules, priority ordering (`client.move`), logging |
| [`ipv4_nat_rules.ipynb`](./ipv4_nat_rules.ipynb) | `Nat` | SNAT, DNAT, Masquerade, rule ordering (`client.move`) |
| [`nested_parameterized_resources.ipynb`](./nested_parameterized_resources.ipynb) | `Logging`, `Authentication`, `ActiveThreatResponse`, `DenialOfService` | In-path substitution: Syslog logs (`GET`/`PATCH`), AD `fetch-groups`, Threat feed `synchronize`, DoS attack stats |
| [`web.ipynb`](./web.ipynb) | `Web` | URL groups, custom categories, content filters, bypass exceptions, web policies, scan settings |

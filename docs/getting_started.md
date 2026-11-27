# Firewall API - Getting Started

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)
[![Development Status: Beta 0.8.0](https://img.shields.io/badge/Status-Beta%200.8.0-orange.svg)](https://pypi.org/project/sfos-api/)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Get up and running with **`sfos-api`** in minutes.

---

## 📦 Installation

Requires Python 3.11 or newer:

```bash
pip install sfos-api
```

Or install in editable mode from the repository:

```bash
pip install -e .
```

To also run the example notebooks with formatted output:

```bash
pip install -e ".[examples]"
```

---

## 🔐 SFOS API Key Setup

1. Sign in to Sophos Firewall WebAdmin (`https://<firewall-host>:4444`).
2. Navigate to **Administration > API** (or **Backup & firmware > API** depending on firmware).
3. Enable REST API access and generate an API key for an administrator profile with the required permissions.
4. Pass the firewall hostname/IP (without `https://`), API key, and port (typically `4444`) to `SFOSClient`.

---

## 🚀 First Script

```python
from sfos_api import SFOSClient, Network, Firewall, ConflictError, SFOSApiError

with SFOSClient("192.168.1.1", "your-api-key", port=4444, verify_ssl=True) as client:
    # 1. Read all zones (auto-paginated)
    zones = client.get(Network.ZONES)
    print(f"Total zones: {len(zones['items'])}")

    # 2. Create an IPv4 host object
    try:
        client.post(
            Network.ADDRESSES_IPV4,
            {"name": "Branch_Router", "ipv4Address": "10.200.1.1", "type": "ipv4Address"},
        )
    except ConflictError:
        # Update existing object if it already exists
        client.patch(
            Network.ADDRESSES_IPV4,
            "Branch_Router",
            data={"description": "Primary edge gateway"},
        )

    # 3. Read firewall rules with custom page size
    rules = client.get(Firewall.RULES_IPV4, pageSize=25)
    print(f"Rules fetched: {len(rules['items'])}")

    # 4. Delete the test host object
    client.delete(Network.ADDRESSES_IPV4, "Branch_Router")
```

> [!TIP]
> For self-signed lab certificates, pass `verify_ssl=False` or a CA bundle path (`verify_ssl="/path/to/ca.pem"`).

---

## 📚 Next Steps

- **[Docs Hub](./README.md)**: Full documentation index
- **[API Reference](./api_reference.md)**: Detailed `get`, `post`, `patch`, `delete`, `move`, `test_connection`, `upload`, and error helpers
- **[Endpoints Reference](./endpoints_reference.md)**: Browse all 27 domain `StrEnum` classes
- **[Examples](../examples/README.md)**: Runnable quickstart and domain notebooks

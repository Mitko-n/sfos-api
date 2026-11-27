# Firewall API - Endpoints Reference <a id="top"></a>

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)
[![Development Status: Beta 0.8.0](https://img.shields.io/badge/Status-Beta%200.8.0-orange.svg)](https://pypi.org/project/sfos-api/)
[![Code Style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Complete catalog of all **27 domain StrEnum classes** and **182 endpoint constants** in `sfos-api`.

**Beta 0.8.0 API:** This catalog is checked against the bundled `Sophos Firewall Configuration OpenAPI specification`. Its metadata lists [Sophos Firewall APIs](https://developer.sophos.com) as the contact and identifies the document as OpenAPI 3.0.0 and API version 1.0.0. This repository does not record the upstream revision or retrieval date, so the file should not be assumed to be the latest release. Endpoint availability can vary by firewall firmware version.

### 📊 Column Schema Legend
- **Endpoint**: Enum member under `sfos_api` (e.g. **`Firewall.RULES_IPV4`**) and its HTTP resource path on Sophos Firewall OS WebAdmin REST API.
- **Supported Methods**: HTTP verbs (`GET`, `POST`, `PATCH`, `DELETE`) defined in OpenAPI.
- **Method Signatures**: Corresponding `SFOSClient` method signatures aligned line-by-line with `Supported Methods`, with helper methods (`client.move`, `client.upload`, `client.test_connection`) on separate lines.
- **Parameters**: Path parameters, operation-specific query parameters, and body requirements. `type` is a query parameter for `Network.SERVICES`; address-object `type` values are body discriminators.
- **Description**: Technical description of the resource or operation aligned with the latest `firewall_config_openapi.yaml` API description.

---

## 🧭 Quick Navigation <a id="quick-navigation"></a>

| Category                                                                                    | Total Domains | Total Endpoints | Jump Link                                                                  |
| ------------------------------------------------------------------------------------------- | :-----------: | :-------------: | -------------------------------------------------------------------------- |
| [**🛡️ 1. Security, Policies & Inspection**](#1-security-policies-inspection)                |       6       |        16       | [Jump to Security Section](#1-security-policies-inspection)                |
| [**🌐 2. Network, Routing & Infrastructure**](#2-network-routing-infrastructure)             |       6       |        54       | [Jump to Network Section](#2-network-routing-infrastructure)               |
| [**🔑 3. Identity, Authentication & Certificates**](#3-identity-authentication-certificates) |       2       |        51       | [Jump to Identity Section](#3-identity-authentication-certificates)        |
| [**🔒 4. VPN & Remote Connectivity**](#4-vpn-remote-connectivity)                            |       2       |        12       | [Jump to VPN Section](#4-vpn-remote-connectivity)                          |
| [**🦠 5. Threat Protection & Content Security**](#5-threat-protection-content-security)      |       6       |        21       | [Jump to Threat Protection Section](#5-threat-protection-content-security) |
| [**⚙️ 6. System, Administration & Observability**](#6-system-administration-observability)  |       5       |        28       | [Jump to System Section](#6-system-administration-observability)           |
| **Total**                                                                                   |     **27**    |     **182**     |                                                                            |

### 🔤 Alphabetical Index
[A](#aclexceptionrules) • [C](#certificate) • [D](#denialofservice) • [F](#firewall) • [I](#intrusionprevention) • [L](#logging) • [M](#malwareprotection) • [N](#network) • [R](#routing) • [S](#sdwan) • [T](#tlsinspection) • [W](#waf) • [Z](#zerodayprotection)

---

## 📑 Table of Domains <a id="table-of-domains"></a>

| Domain Class                                        | Category            | Endpoints | Scope & Primary Resources                               | Quick Import                                |
| --------------------------------------------------- | ------------------- | :-------: | ------------------------------------------------------- | ------------------------------------------- |
| [**`AclExceptionRules`**](#aclexceptionrules)       | 🛡️ Security         |     2     | IPv4 and IPv6 ACL exception bypass rules                | `from sfos_api import AclExceptionRules`    |
| [**`ActiveThreatResponse`**](#activethreatresponse) | 🦠 Threat Protection |     5     | MDR feeds, Sophos X-Ops, 3rd-party feeds & sync         | `from sfos_api import ActiveThreatResponse` |
| [**`Administration`**](#administration)             | ⚙️ System           |     8     | Access permissions, profiles, API, portal, schedules    | `from sfos_api import Administration`       |
| [**`Application`**](#application)                   | 🦠 Threat Protection |     5     | App definitions, categories, attributes, policy filters | `from sfos_api import Application`          |
| [**`Authentication`**](#authentication)             | 🔑 Identity          |     43    | Users, groups, AD/LDAP/RADIUS/TACACS, TOTP/MFA, SSO     | `from sfos_api import Authentication`       |
| [**`Certificate`**](#certificate)                   | 🔑 Identity          |     8     | CAs, internal/external certificates, CSRs, CRLs         | `from sfos_api import Certificate`          |
| [**`DenialOfService`**](#denialofservice)           | 🛡️ Security         |     3     | DoS flood attack protection, thresholds, telemetry      | `from sfos_api import DenialOfService`      |
| [**`Firewall`**](#firewall)                         | 🛡️ Security         |     2     | IPv4 and IPv6 stateful traffic filtering rules          | `from sfos_api import Firewall`             |
| [**`IntrusionPrevention`**](#intrusionprevention)   | 🛡️ Security         |     4     | IPS policies, custom signatures, engine settings        | `from sfos_api import IntrusionPrevention`  |
| [**`IpsecVpn`**](#ipsecvpn)                         | 🔒 VPN               |     7     | Site-to-site (policy/route-based), profiles, failover   | `from sfos_api import IpsecVpn`             |
| [**`Logging`**](#logging)                           | ⚙️ System           |     7     | Syslog servers, Central reporting, log viewer, events   | `from sfos_api import Logging`              |
| [**`MalwareProtection`**](#malwareprotection)       | 🦠 Threat Protection |     1     | Global anti-malware scanning engine settings            | `from sfos_api import MalwareProtection`    |
| [**`Monitoring`**](#monitoring)                     | ⚙️ System           |     4     | NetFlow collectors, SNMP agents, communities, users     | `from sfos_api import Monitoring`           |
| [**`Nat`**](#nat)                                   | 🛡️ Security         |     2     | IPv4 and IPv6 NAT (SNAT, DNAT, 1:1) rules               | `from sfos_api import Nat`                  |
| [**`Network`**](#network)                           | 🌐 Network           |    35     | Interfaces, IP/FQDN/MAC hosts, groups, DHCP, DNS        | `from sfos_api import Network`              |
| [**`Notification`**](#notification)                 | ⚙️ System           |     1     | Alert notifications and administrative recipients       | `from sfos_api import Notification`         |
| [**`Routing`**](#routing)                           | 🌐 Network           |     10    | Gateways (custom/WAN), static unicast/multicast routes  | `from sfos_api import Routing`              |
| [**`SdWan`**](#sdwan)                               | 🌐 Network           |     2     | Policy-based SD-WAN routing paths for IPv4 and IPv6     | `from sfos_api import SdWan`                |
| [**`SpoofProtection`**](#spoofprotection)           | 🌐 Network           |     3     | IP/MAC spoof prevention and trusted MAC database        | `from sfos_api import SpoofProtection`      |
| [**`SslVpn`**](#sslvpn)                             | 🔒 VPN               |     5     | SSL VPN remote access policies & clientless bookmarks   | `from sfos_api import SslVpn`               |
| [**`System`**](#system)                             | ⚙️ System           |     4     | Backup, hotfixes, security patterns, firmware updates   | `from sfos_api import System`               |
| [**`TlsInspection`**](#tlsinspection)               | 🛡️ Security         |     3     | TLS/SSL decryption profiles, inspection rules, engine   | `from sfos_api import TlsInspection`        |
| [**`TrafficShaping`**](#trafficshaping)             | 🌐 Network           |     2     | QoS bandwidth allocation policies and limits            | `from sfos_api import TrafficShaping`       |
| [**`Waf`**](#waf)                                   | 🦠 Threat Protection |     4     | Web Application Firewall protection policies & servers  | `from sfos_api import Waf`                  |
| [**`Web`**](#web)                                   | 🦠 Threat Protection |     8     | Web filtering policies, categories, exceptions, URLs    | `from sfos_api import Web`                  |
| [**`Wireless`**](#wireless)                         | 🌐 Network           |     3     | Wireless hotspots, guest voucher generation, portals    | `from sfos_api import Wireless`             |
| [**`ZeroDayProtection`**](#zerodayprotection)       | 🦠 Threat Protection |     1     | Sandstorm cloud sandboxing analysis settings            | `from sfos_api import ZeroDayProtection`    |

<a id="1-security-policies-inspection"></a><a id="1-security-policies--inspection"></a>
## 1. Security, Policies & Inspection

🛡️ Security policies, rulebases, NAT translation, attack prevention, and deep packet inspection.

### <a id="aclexceptionrules"></a>`AclExceptionRules`

Import: `from sfos_api import AclExceptionRules`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`AclExceptionRules.IPV4`**<br><br>/acl-exception-rules/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IPv4 ACL exception / bypass rulebase                               |
| **`AclExceptionRules.IPV6`**<br><br>/acl-exception-rules/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IPv6 ACL exception / bypass rulebase                               |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="denialofservice"></a>`DenialOfService`

Import: `from sfos_api import DenialOfService`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`DenialOfService.ATTACKS_BY_FLOOD_ATTACK_TYPE`**<br><br>/denial-of-service/attacks/{floodAttackType} | `GET` | `client.get(endpoint, id_or_name)` | Path: `floodAttackType` *(required)*                                                                                                    | Flood attack telemetry filtered by attack type (SYN, UDP, ICMP)    |
| **`DenialOfService.ATTACKS_SUMMARY`**<br><br>/denial-of-service/attacks/summary | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Aggregate statistical summary of detected DoS attacks              |
| **`DenialOfService.POLICIES`**<br><br>/denial-of-service/policies | `GET`<br>`POST`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | DoS protection rate-limiting and threshold policies                |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="firewall"></a>`Firewall`

Import: `from sfos_api import Firewall`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Firewall.RULES_IPV4`**<br><br>/firewall/rules/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.move(endpoint, data)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IPv4 stateful firewall rules and policy ordering                   |
| **`Firewall.RULES_IPV6`**<br><br>/firewall/rules/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.move(endpoint, data)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IPv6 stateful firewall rules and policy ordering                   |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="intrusionprevention"></a>`IntrusionPrevention`

Import: `from sfos_api import IntrusionPrevention`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`IntrusionPrevention.CUSTOM_SIGNATURES`**<br><br>/intrusion-prevention/custom-signatures | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | User-defined custom IPS pattern signatures                         |
| **`IntrusionPrevention.POLICIES`**<br><br>/intrusion-prevention/policies | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | IPS filtering policies and protection categories                   |
| **`IntrusionPrevention.SETTINGS`**<br><br>/intrusion-prevention/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Global IPS engine configuration and fail-open settings             |
| **`IntrusionPrevention.SIGNATURE_ATTRIBUTES`**<br><br>/intrusion-prevention/signature-attributes | `GET` | `client.get(endpoint, [id_or_name])` | Path: `name` *(item)*                                                                                                                   | Signature attribute metadata (severity, target, platform)          |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="nat"></a>`Nat`

Import: `from sfos_api import Nat`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Nat.RULES_IPV4`**<br><br>/nat/rules/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.move(endpoint, data)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IPv4 SNAT, DNAT, and full NAT translation rules                    |
| **`Nat.RULES_IPV6`**<br><br>/nat/rules/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.move(endpoint, data)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IPv6 NAT translation rules and prefix mappings                     |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="tlsinspection"></a>`TlsInspection`

Import: `from sfos_api import TlsInspection`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`TlsInspection.DECRYPTION_PROFILES`**<br><br>/tls-inspection/decryption-profiles | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | TLS decryption profiles, ciphers, and protocol minimums            |
| **`TlsInspection.RULES_IPV4`**<br><br>/tls-inspection/rules/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.move(endpoint, data)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IPv4 SSL/TLS inspection and bypass rules                           |
| **`TlsInspection.SETTINGS`**<br><br>/tls-inspection/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Global TLS engine and hardware acceleration settings               |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

<a id="2-network-routing-infrastructure"></a><a id="2-network-routing--infrastructure"></a>
## 2. Network, Routing & Infrastructure

🌐 Core network configuration, physical and virtual interfaces, DHCP, DNS, IP objects, routing, and cellular WAN.

### <a id="network"></a>`Network`

Import: `from sfos_api import Network`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Network.ADDRESSES_FQDN`**<br><br>/network/addresses/fqdn | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Fully Qualified Domain Name (FQDN) network host objects            |
| **`Network.ADDRESSES_IPV4`**<br><br>/network/addresses/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`<br>Body discriminator: `type` (`ipv4Address`, `ipv4Network`, `ipv4Range`, `ipv4List`) | IPv4 host, network, IP range, and IP list objects                  |
| **`Network.ADDRESSES_IPV6`**<br><br>/network/addresses/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`<br>Body discriminator: `type` (`ipv6Address`, `ipv6Network`, `ipv6Range`, `ipv6List`) | IPv6 host, network, and IP range objects                           |
| **`Network.ADDRESSES_MAC`**<br><br>/network/addresses/mac | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`<br>Body discriminator: `type` (`macAddress`, `macList`) | MAC address host definitions                                       |
| **`Network.ADDRESS_GROUPS_COUNTRY`**<br><br>/network/address-groups/country | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | GeoIP country and regional location groups                         |
| **`Network.ADDRESS_GROUPS_FQDN`**<br><br>/network/address-groups/fqdn | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Groupings of FQDN host objects                                     |
| **`Network.ADDRESS_GROUPS_IPV4`**<br><br>/network/address-groups/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Groupings of IPv4 host and network objects                         |
| **`Network.ADDRESS_GROUPS_IPV6`**<br><br>/network/address-groups/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Groupings of IPv6 host and network objects                         |
| **`Network.CELLULAR_WAN_CONNECT_MODEM`**<br><br>/network/cellular-wan/connect-modem | `POST` | `client.post(endpoint)` | None *(singleton)*                                                                                                                      | Action: Connect cellular WAN modem interface                       |
| **`Network.CELLULAR_WAN_DISCONNECT_MODEM`**<br><br>/network/cellular-wan/disconnect-modem | `POST` | `client.post(endpoint)` | None *(singleton)*                                                                                                                      | Action: Disconnect cellular WAN modem interface                    |
| **`Network.CELLULAR_WAN_MODEM_SETTINGS`**<br><br>/network/cellular-wan/modem-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Cellular WAN modem configuration (APN, PIN, auth)                  |
| **`Network.CELLULAR_WAN_MODEM_STATUS`**<br><br>/network/cellular-wan/modem-status | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Real-time signal strength, carrier, and link status                |
| **`Network.CELLULAR_WAN_RECOMMENDED_MODEM_SETTINGS`**<br><br>/network/cellular-wan/recommended-modem-settings | `POST` | `client.post(endpoint)` | None *(singleton)*                                                                                                                      | Carrier profile presets and recommended parameters                 |
| **`Network.CELLULAR_WAN_RESET_MODEM`**<br><br>/network/cellular-wan/reset-modem | `POST` | `client.post(endpoint)` | None *(singleton)*                                                                                                                      | Action: Power cycle or soft reset cellular modem                   |
| **`Network.CELLULAR_WAN_SETTINGS`**<br><br>/network/cellular-wan/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | General cellular WAN daemon configuration                          |
| **`Network.DHCP_RELAYS_IPV4`**<br><br>/network/dhcp/relays/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | IPv4 DHCP relay forwarders                                         |
| **`Network.DHCP_RELAYS_IPV6`**<br><br>/network/dhcp/relays/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | IPv6 DHCP relay forwarders                                         |
| **`Network.DHCP_SERVER_LEASES_IPV4`**<br><br>/network/dhcp/server/leases/ipv4 | `GET` | `client.get(endpoint)` | None                                                                                                                                     | Active IPv4 DHCP leases                                            |
| **`Network.DHCP_SERVER_LEASES_IPV6`**<br><br>/network/dhcp/server/leases/ipv6 | `GET` | `client.get(endpoint)` | None                                                                                                                                     | Active IPv6 DHCP leases                                            |
| **`Network.DHCP_SERVER_SERVERS_IPV4`**<br><br>/network/dhcp/server/servers/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | IPv4 DHCP server scope configurations                              |
| **`Network.DHCP_SERVER_SERVERS_IPV6`**<br><br>/network/dhcp/server/servers/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | IPv6 DHCP server scope configurations                              |
| **`Network.DHCP_SERVER_SETTINGS_IPV4`**<br><br>/network/dhcp/server/settings/ipv4 | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Global DHCP daemon settings for IPv4                               |
| **`Network.DNS_HOST_ENTRIES`**<br><br>/network/dns/host-entries | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Static DNS host mappings (A, AAAA, PTR records)                    |
| **`Network.DNS_PROTECTION_STATUS`**<br><br>/network/dns/protection/status | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | DNS threat protection status and telemetry                         |
| **`Network.DNS_REQUEST_ROUTES`**<br><br>/network/dns/request-routes | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Conditional DNS request routing by domain                          |
| **`Network.DNS_SETTINGS`**<br><br>/network/dns/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Primary, secondary, and upstream DNS servers                       |
| **`Network.INTERFACES_NETWORK_INTERFACES`**<br><br>/network/interfaces/network-interfaces | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Physical, VLAN, bridge, and LAG network interfaces                 |
| **`Network.MDNS_REFLECTOR`**<br><br>/network/mdns-reflector | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Multicast DNS (mDNS) reflector across zones                        |
| **`Network.NEIGHBORS_SETTINGS`**<br><br>/network/neighbors/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | ARP and IPv6 neighbor discovery cache parameters                   |
| **`Network.NEIGHBORS_STATIC_IPV4`**<br><br>/network/neighbors/static/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Static IPv4 ARP table mappings                                     |
| **`Network.NEIGHBORS_STATIC_IPV6`**<br><br>/network/neighbors/static/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Static IPv6 neighbor cache entries                                 |
| **`Network.ROUTER_ADVERTISEMENTS`**<br><br>/network/router-advertisements | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IPv6 Router Advertisement (RA) daemon daemon rules                 |
| **`Network.SERVICES`**<br><br>/network/services | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `type` (`tcpOrUdp`, `ip`, `icmp`, `icmpv6`), `page`, `pageSize`, `pageTotal`                    | Custom TCP/UDP/IP protocol service definitions                     |
| **`Network.SERVICE_GROUPS`**<br><br>/network/service-groups | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Groupings of protocol service objects                              |
| **`Network.ZONES`**<br><br>/network/zones | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Security zones (LAN, WAN, DMZ, VPN, WiFi)                          |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="routing"></a>`Routing`

Import: `from sfos_api import Routing`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Routing.GATEWAYS_CUSTOM_IPV4`**<br><br>/routing/gateways/custom/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Custom defined IPv4 next-hop gateways                              |
| **`Routing.GATEWAYS_CUSTOM_IPV6`**<br><br>/routing/gateways/custom/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Custom defined IPv6 next-hop gateways                              |
| **`Routing.GATEWAYS_IPV4`**<br><br>/routing/gateways/ipv4 | `GET` | `client.get(endpoint)` | Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                                                | Active IPv4 gateways and routing table status                      |
| **`Routing.GATEWAYS_IPV6`**<br><br>/routing/gateways/ipv6 | `GET` | `client.get(endpoint)` | Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                                                | Active IPv6 gateways and routing table status                      |
| **`Routing.GATEWAYS_WAN_IPV4`**<br><br>/routing/gateways/wan/ipv4 | `GET`<br>`PATCH` | `client.get(endpoint, [id_or_name])`<br>`client.patch(endpoint, id_or_name, data=data)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | WAN uplink IPv4 gateways and failover weights                      |
| **`Routing.GATEWAYS_WAN_IPV6`**<br><br>/routing/gateways/wan/ipv6 | `GET`<br>`PATCH` | `client.get(endpoint, [id_or_name])`<br>`client.patch(endpoint, id_or_name, data=data)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | WAN uplink IPv6 gateways and failover weights                      |
| **`Routing.STATIC_MULTICAST_ROUTES_IPV4`**<br><br>/routing/static-multicast-routes/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | Static multicast routes for IPv4 streams                           |
| **`Routing.STATIC_MULTICAST_SETTINGS`**<br><br>/routing/static-multicast-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Global multicast routing configuration                             |
| **`Routing.STATIC_UNICAST_ROUTES_IPV4`**<br><br>/routing/static-unicast-routes/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | Static unicast routes for IPv4 networks                            |
| **`Routing.STATIC_UNICAST_ROUTES_IPV6`**<br><br>/routing/static-unicast-routes/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | Static unicast routes for IPv6 networks                            |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="sdwan"></a>`SdWan`

Import: `from sfos_api import SdWan`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`SdWan.ROUTES_IPV4`**<br><br>/sd-wan/routes/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.move(endpoint, data)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Policy-based SD-WAN routing rules for IPv4 traffic                 |
| **`SdWan.ROUTES_IPV6`**<br><br>/sd-wan/routes/ipv6 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.move(endpoint, data)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Policy-based SD-WAN routing rules for IPv6 traffic                 |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="spoofprotection"></a>`SpoofProtection`

Import: `from sfos_api import SpoofProtection`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`SpoofProtection.SETTINGS`**<br><br>/spoof-protection/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | IP/MAC spoof protection filters and drop behavior                  |
| **`SpoofProtection.TRUSTED_MACS`**<br><br>/spoof-protection/trusted-macs | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Database of trusted MAC/IP address pairings                        |
| **`SpoofProtection.TRUSTED_MACS_IMPORT`**<br><br>/spoof-protection/trusted-macs/import | `POST`<br>&nbsp; | `client.post(endpoint, files=...)`<br>`client.upload(endpoint, file)` | Body: `multipart/form-data` (`file`: CSV or TXT file)                                                                                   | Action: Batch import trusted MAC addresses via CSV/TXT file        |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="trafficshaping"></a>`TrafficShaping`

Import: `from sfos_api import TrafficShaping`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`TrafficShaping.POLICIES`**<br><br>/traffic-shaping/policies | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | QoS bandwidth allocation policies, burst limits, and priorities    |
| **`TrafficShaping.SETTINGS`**<br><br>/traffic-shaping/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Global traffic shaping and total link bandwidth parameters         |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="wireless"></a>`Wireless`

Import: `from sfos_api import Wireless`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Wireless.HOTSPOT_HOTSPOTS`**<br><br>/wireless/hotspot/hotspots | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Wireless guest hotspots and landing pages                          |
| **`Wireless.HOTSPOT_SETTINGS`**<br><br>/wireless/hotspot/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Hotspot terms of service and redirect settings                     |
| **`Wireless.HOTSPOT_VOUCHERS`**<br><br>/wireless/hotspot/vouchers | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Guest access time/quota voucher generator                          |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

<a id="3-identity-authentication-certificates"></a><a id="3-identity-authentication--certificates"></a>
## 3. Identity, Authentication & Certificates

🔑 User directories, external identity providers, captive portal, MFA/TOTP tokens, and X.509 certificate management.

### <a id="authentication"></a>`Authentication`

Import: `from sfos_api import Authentication`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Authentication.ADMIN_USER_PASSWORD`**<br><br>/authentication/admin-user/password | `POST` | `client.post(endpoint, data)` | Body: JSON payload                                                                                                                      | Action: Update built-in administrator account password             |
| **`Authentication.CAPTIVE_PORTAL_APPEARANCE`**<br><br>/authentication/captive-portal/appearance | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Captive portal logo, branding, and styling settings                |
| **`Authentication.CLIENTS_GLOBAL_SETTINGS`**<br><br>/authentication/clients/global-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Authentication client software global parameters                   |
| **`Authentication.CLIENTS_TRANSPARENT_AUTH_SUITE_COLLECTORS`**<br><br>/authentication/clients/transparent-auth-suite/collectors | `GET`<br>`POST`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                 | STAS (Sophos Transparent Authentication) collector agents          |
| **`Authentication.CLIENTS_TRANSPARENT_AUTH_SUITE_SETTINGS`**<br><br>/authentication/clients/transparent-auth-suite/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | STAS transparent single sign-on settings                           |
| **`Authentication.CLIENTS_TRANSPARENT_AUTH_SUITE_VPN_SOURCE_NETWORKS`**<br><br>/authentication/clients/transparent-auth-suite/vpn-source-networks | `GET`<br>`POST`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                               | STAS IP source subnets for VPN clients                             |
| **`Authentication.GUEST_USER_SETTINGS_SMS_GATEWAYS`**<br><br>/authentication/guest-user-settings/sms-gateways | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.test_connection(endpoint, [data])` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | SMS gateway configurations for guest OTP delivery                  |
| **`Authentication.LIVE_USERS`**<br><br>/authentication/live-users | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Real-time active authenticated user sessions                       |
| **`Authentication.LIVE_USERS_DISCONNECT`**<br><br>/authentication/live-users/disconnect | `POST` | `client.post(endpoint, data)` | Body: JSON payload                                                                                                                      | Action: Force disconnect one or more live user sessions            |
| **`Authentication.LOGIN_SECURITY_SETTINGS`**<br><br>/authentication/login/security-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Brute-force lockout and session timeout parameters                 |
| **`Authentication.MULTI_FACTOR_AUTHENTICATION_TOTP_SETTINGS`**<br><br>/authentication/multi-factor-authentication/totp-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | TOTP MFA configuration and portal enrollment rules                 |
| **`Authentication.MULTI_FACTOR_AUTHENTICATION_TOTP_TOKENS`**<br><br>/authentication/multi-factor-authentication/totp-tokens | `GET` | `client.get(endpoint)` | Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                              | Registered TOTP tokens inventory                                   |
| **`Authentication.MULTI_FACTOR_AUTHENTICATION_TOTP_TOKENS_HARDWARE_TOKENS`**<br><br>/authentication/multi-factor-authentication/totp-tokens/hardware-tokens | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                               | Pre-shared secret hardware OTP key fobs                            |
| **`Authentication.MULTI_FACTOR_AUTHENTICATION_TOTP_TOKENS_SOFTWARE_TOKENS`**<br><br>/authentication/multi-factor-authentication/totp-tokens/software-tokens | `GET` | `client.get(endpoint)` | Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                              | Software authenticator apps (Sophos/Google Authenticator)          |
| **`Authentication.PASSWORD_COMPLEXITY_ADMINISTRATIVE_USERS`**<br><br>/authentication/password-complexity/administrative-users | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Password complexity rules for firewall administrators              |
| **`Authentication.PASSWORD_COMPLEXITY_NETWORK_USERS`**<br><br>/authentication/password-complexity/network-users | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Password complexity rules for standard network users               |
| **`Authentication.POLICIES_ACCESS_TIMES`**<br><br>/authentication/policies/access-times | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | Allowed login time schedules and restrictions                      |
| **`Authentication.POLICIES_NETWORK_TRAFFIC_QUOTAS`**<br><br>/authentication/policies/network-traffic-quotas | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | Data transfer volume quota limits per user                         |
| **`Authentication.POLICIES_SURFING_QUOTAS`**<br><br>/authentication/policies/surfing-quotas | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                               | Web surfing time allowance quotas                                  |
| **`Authentication.SERVERS`**<br><br>/authentication/servers | `GET`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Directory and authentication servers overview                      |
| **`Authentication.SERVERS_ACTIVE_DIRECTORY`**<br><br>/authentication/servers/active-directory | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.test_connection(endpoint, [data])` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | Microsoft Active Directory domain controller connections           |
| **`Authentication.SERVERS_ACTIVE_DIRECTORY_BY_ID_OR_NAME_FETCH_GROUPS`**<br><br>/authentication/servers/active-directory/{idOrName}/fetch-groups | `POST` | `client.post(endpoint, data, id_or_name=...)` | Path: `idOrName` *(required)*                                                                                                           | Action: Query and import AD security groups                        |
| **`Authentication.SERVERS_GENERIC_IDP_SSO`**<br><br>/authentication/servers/generic-idp-sso | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.test_connection(endpoint, [data])` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | OpenID Connect (OIDC) / SAML generic IdP configurations            |
| **`Authentication.SERVERS_GENERIC_IDP_SSO_BY_ID_OR_NAME_FETCH_GROUPS`**<br><br>/authentication/servers/generic-idp-sso/{idOrName}/fetch-groups | `POST` | `client.post(endpoint, data, id_or_name=...)` | Path: `idOrName` *(required)*                                                                                                           | Action: Discover and import IdP role claims / groups               |
| **`Authentication.SERVERS_GENERIC_IDP_SSO_OIDC_DISCOVERY`**<br><br>/authentication/servers/generic-idp-sso/oidc-discovery | `POST` | `client.post(endpoint, data)` | Body: JSON payload                                                                                                                      | Action: Auto-discover IdP configuration via `.well-known` endpoint |
| **`Authentication.SERVERS_LDAP`**<br><br>/authentication/servers/ldap | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.test_connection(endpoint, [data])` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | OpenLDAP and standard LDAP directory connections                   |
| **`Authentication.SERVERS_LDAP_FETCH_BASE_DN`**<br><br>/authentication/servers/ldap/fetch-base-dn | `POST` | `client.post(endpoint, data)` | Body: JSON payload                                                                                                                      | Action: Discover and query directory Base DN from LDAP             |
| **`Authentication.SERVERS_RADIUS`**<br><br>/authentication/servers/radius | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.test_connection(endpoint, [data])` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | RADIUS server definitions for AAA authentication                   |
| **`Authentication.SERVERS_TACACS`**<br><br>/authentication/servers/tacacs | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.test_connection(endpoint, [data])` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                   | TACACS+ administrative authentication servers                      |
| **`Authentication.SERVER_PRIORITY_LIST_ADMINISTRATIVE_ACCESS`**<br><br>/authentication/server-priority-list/administrative-access | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Authentication server fallback sequence for administrators         |
| **`Authentication.SERVER_PRIORITY_LIST_DEFAULT`**<br><br>/authentication/server-priority-list/default | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Default authentication server fallback sequence                    |
| **`Authentication.SERVER_PRIORITY_LIST_USER_PORTAL_ACCESS`**<br><br>/authentication/server-priority-list/user-portal-access | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Authentication fallback sequence for User Portal                   |
| **`Authentication.SERVER_PRIORITY_LIST_VPN_ACCESS`**<br><br>/authentication/server-priority-list/vpn-access | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Authentication fallback sequence for SSL/IPsec VPN                 |
| **`Authentication.SERVICES_CHROMEBOOK_SSO`**<br><br>/authentication/services/chromebook-sso | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | G Suite / Google Chromebook Single Sign-On service                 |
| **`Authentication.SERVICES_RADIUS_ACCOUNTING_SSO`**<br><br>/authentication/services/radius-accounting-sso | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                 | RADIUS Accounting SSO integration settings                         |
| **`Authentication.USERS`**<br><br>/authentication/users | `GET` | `client.get(endpoint)` | Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                              | All local and synchronized user accounts                           |
| **`Authentication.USERS_ADMINISTRATORS`**<br><br>/authentication/users/administrators | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                               | Firewall administrative user accounts                              |
| **`Authentication.USERS_NETWORK_USERS`**<br><br>/authentication/users/network-users | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                               | Standard network and VPN user accounts                             |
| **`Authentication.USERS_NETWORK_USERS_LOGIN`**<br><br>/authentication/users/network-users/login | `POST` | `client.post(endpoint, data)` | Body: JSON payload                                                                                                                      | Action: Trigger programmatic user login                            |
| **`Authentication.USERS_NETWORK_USERS_LOGOUT`**<br><br>/authentication/users/network-users/logout | `POST` | `client.post(endpoint, data)` | Body: JSON payload                                                                                                                      | Action: Trigger programmatic user logout                           |
| **`Authentication.USER_GROUPS`**<br><br>/authentication/user-groups | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Local and synchronized user groups                                 |
| **`Authentication.USER_GROUPS_SET_FALLBACK_GROUP`**<br><br>/authentication/user-groups/set-fallback-group | `POST` | `client.post(endpoint, data)` | Body: JSON payload                                                                                                                      | Action: Set default fallback user group for new users              |
| **`Authentication.WEB_SETTINGS`**<br><br>/authentication/web-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Captive portal redirection and re-authentication settings          |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="certificate"></a>`Certificate`

Import: `from sfos_api import Certificate`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Certificate.CERTIFICATES`**<br><br>/certificate/certificates | `GET` | `client.get(endpoint)` | Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                                                | All installed X.509 server and user certificates                   |
| **`Certificate.CERTIFICATES_CERTIFICATE_SIGNING_REQUESTS`**<br><br>/certificate/certificates/certificate-signing-requests | `GET`<br>`POST`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Certificate Signing Requests (CSR) management                      |
| **`Certificate.CERTIFICATES_EXTERNAL`**<br><br>/certificate/certificates/external | `GET`<br>`POST`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Third-party issued external certificates                           |
| **`Certificate.CERTIFICATES_INTERNAL`**<br><br>/certificate/certificates/internal | `GET`<br>`POST`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Locally signed internal private certificates                       |
| **`Certificate.CERTIFICATE_AUTHORITIES`**<br><br>/certificate/certificate-authorities | `GET`<br>`POST`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Trusted Root and Intermediate Certificate Authorities              |
| **`Certificate.CERTIFICATE_AUTHORITIES_BUILT_IN_DEFAULT_CA`**<br><br>/certificate/certificate-authorities/built-in/default-ca | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Sophos Appliance built-in default CA details                       |
| **`Certificate.CERTIFICATE_AUTHORITIES_BUILT_IN_DEFAULT_CA_REGENERATE`**<br><br>/certificate/certificate-authorities/built-in/default-ca/regenerate | `POST` | `client.post(endpoint, data)` | Body: JSON payload                                                                                                                      | Action: Regenerate built-in default CA certificate                 |
| **`Certificate.CERTIFICATE_REVOCATION_LISTS`**<br><br>/certificate/certificate-revocation-lists | `GET`<br>`POST`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Certificate Revocation Lists (CRL) and auto-sync                   |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

<a id="4-vpn-remote-connectivity"></a><a id="4-vpn--remote-connectivity"></a>
## 4. VPN & Remote Connectivity

🔒 Site-to-site IPsec tunnels, route/policy-based connections, and SSL VPN remote access.

### <a id="ipsecvpn"></a>`IpsecVpn`

Import: `from sfos_api import IpsecVpn`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`IpsecVpn.PROFILES`**<br><br>/ipsec-vpn/profiles | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IKEv1/IKEv2 cryptographic negotiation profiles                     |
| **`IpsecVpn.REMOTE_ACCESS_SETTINGS`**<br><br>/ipsec-vpn/remote-access/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | IPsec remote access client pool and gateway settings               |
| **`IpsecVpn.SITE_TO_SITE_CONNECTIONS_IPV4`**<br><br>/ipsec-vpn/site-to-site/connections/ipv4 | `GET`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | IPv4 IPsec site-to-site connection profiles                        |
| **`IpsecVpn.SITE_TO_SITE_CONNECTIONS_POLICY_BASED_IPV4`**<br><br>/ipsec-vpn/site-to-site/connections/policy-based/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Policy-based (crypto map) IPv4 site-to-site tunnels                |
| **`IpsecVpn.SITE_TO_SITE_CONNECTIONS_ROUTE_BASED_IPV4`**<br><br>/ipsec-vpn/site-to-site/connections/route-based/ipv4 | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Route-based (XFRM tunnel interface) IPv4 IPsec connections         |
| **`IpsecVpn.SITE_TO_SITE_FAILOVER_GROUPS`**<br><br>/ipsec-vpn/site-to-site/failover-groups | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `filter`, `sort`, `page`, `pageSize`, `pageTotal`                             | Redundant multi-tunnel failover groups                             |
| **`IpsecVpn.SITE_TO_SITE_LIVE_CONNECTIONS_IPV4`**<br><br>/ipsec-vpn/site-to-site/live-connections/ipv4 | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Real-time active IPsec tunnel status and SA diagnostics            |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="sslvpn"></a>`SslVpn`

Import: `from sfos_api import SslVpn`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`SslVpn.CLIENTLESS_BOOKMARKS`**<br><br>/ssl-vpn/clientless/bookmarks | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | HTML5 clientless browser bookmarks (RDP, SSH, VNC, HTTP)           |
| **`SslVpn.CLIENTLESS_BOOKMARK_GROUPS`**<br><br>/ssl-vpn/clientless/bookmark-groups | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Bookmark group assignments for clientless access                   |
| **`SslVpn.CLIENTLESS_POLICIES`**<br><br>/ssl-vpn/clientless/policies | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Clientless SSL VPN portal access permissions                       |
| **`SslVpn.GLOBAL_SETTINGS`**<br><br>/ssl-vpn/global-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | OpenVPN protocol, port, cipher, and IP lease pool parameters       |
| **`SslVpn.REMOTE_ACCESS_POLICIES`**<br><br>/ssl-vpn/remote-access/policies | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Full-tunnel and split-tunnel remote access client policies         |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

<a id="5-threat-protection-content-security"></a><a id="5-threat-protection--content-security"></a>
## 5. Threat Protection & Content Security

🦠 Threat intelligence feeds, MDR, Application Control, Antivirus, Web Content Filtering, WAF, and Cloud Sandboxing.

### <a id="activethreatresponse"></a>`ActiveThreatResponse`

Import: `from sfos_api import ActiveThreatResponse`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`ActiveThreatResponse.MDR_THREAT_FEED_SETTINGS`**<br><br>/active-threat-response/mdr-threat-feed/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Sophos MDR (Managed Detection and Response) threat feed feeds      |
| **`ActiveThreatResponse.SOPHOS_X_OPS_THREAT_FEED_SETTINGS`**<br><br>/active-threat-response/sophos-x-ops-threat-feed/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Sophos X-Ops threat intelligence feed parameters                   |
| **`ActiveThreatResponse.THIRDPARTY_THREAT_FEEDS`**<br><br>/active-threat-response/thirdparty-threat-feeds | `GET`<br>`POST`<br>`PATCH`<br>`DELETE`<br>&nbsp; | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)`<br>`client.test_connection(endpoint, [data])` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                 | Custom STIX/TAXII and URL third-party threat feeds                 |
| **`ActiveThreatResponse.THIRDPARTY_THREAT_FEEDS_BY_ID_OR_NAME_SYNCHRONIZE`**<br><br>/active-threat-response/thirdparty-threat-feeds/{idOrName}/synchronize | `POST` | `client.post(endpoint, id_or_name=...)` | Path: `idOrName` *(required)*                                                                                                           | Action: Trigger immediate threat feed pull and synchronization     |
| **`ActiveThreatResponse.THREAT_EXCLUSIONS`**<br><br>/active-threat-response/threat-exclusions | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Whitelisted IOCs and IP/domain threat exclusions                   |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="application"></a>`Application`

Import: `from sfos_api import Application`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Application.APPS`**<br><br>/application/apps | `GET`<br>`PATCH` | `client.get(endpoint, [id_or_name])`<br>`client.patch(endpoint, id_or_name, data=data)` | Path: `name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                      | Known application signature definitions catalog                    |
| **`Application.ATTRIBUTES`**<br><br>/application/attributes | `GET` | `client.get(endpoint, [id_or_name])` | Path: `name` *(item)*                                                                                                                   | Application risk levels, categories, and technology tags           |
| **`Application.CATEGORIES`**<br><br>/application/categories | `GET`<br>`PATCH` | `client.get(endpoint, [id_or_name])`<br>`client.patch(endpoint, id_or_name, data=data)` | Path: `name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                      | High-level application categories (P2P, Streaming, Games)          |
| **`Application.OBJECTS`**<br><br>/application/objects | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | Application filter objects and custom signatures                   |
| **`Application.POLICIES`**<br><br>/application/policies | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | Application control filtering policies and actions                 |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="malwareprotection"></a>`MalwareProtection`

Import: `from sfos_api import MalwareProtection`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`MalwareProtection.SETTINGS`**<br><br>/malware-protection/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Dual-engine antivirus scanning settings and file size limits       |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="waf"></a>`Waf`

Import: `from sfos_api import Waf`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Waf.AUTHENTICATION_POLICIES`**<br><br>/waf/authentication/policies | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | Reverse proxy client authentication policies                       |
| **`Waf.AUTHENTICATION_TEMPLATES`**<br><br>/waf/authentication/templates | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | Reverse proxy login form templates                                 |
| **`Waf.PROTECTION_POLICIES`**<br><br>/waf/protection/policies | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `name`, `page`, `pageSize`, `pageTotal`                                                                        | Web Application Firewall SQLi, XSS, and cookie protection          |
| **`Waf.SERVERS`**<br><br>/waf/servers | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `page`, `pageSize`, `pageTotal`                                                                                | Backend web servers and host farm configurations                   |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="web"></a>`Web`

Import: `from sfos_api import Web`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Web.CATEGORIES`**<br><br>/web/categories | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Web filtering categories (standard and custom)                     |
| **`Web.CONTENT_FILTERS`**<br><br>/web/content-filters | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | File extension, MIME type, and keyword content filters             |
| **`Web.EXCEPTIONS`**<br><br>/web/exceptions | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | URL bypass and scanning exception lists                            |
| **`Web.POLICIES`**<br><br>/web/policies | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Web protection rules, user quotas, and schedule assignments        |
| **`Web.SCAN_SETTINGS`**<br><br>/web/scan-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | HTTP/HTTPS proxy inspection modes and block page settings          |
| **`Web.URL_GROUPS`**<br><br>/web/url-groups | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Custom URL and domain groups for filtering                         |
| **`Web.USER_ACTIVITIES`**<br><br>/web/user-activities | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Productive vs. unproductive user browsing classification           |
| **`Web.USER_NOTIFICATIONS`**<br><br>/web/user-notifications | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Block page banners and warning notification pages                  |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="zerodayprotection"></a>`ZeroDayProtection`

Import: `from sfos_api import ZeroDayProtection`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`ZeroDayProtection.SETTINGS`**<br><br>/zero-day-protection/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Sophos Sandstorm cloud sandboxing analysis parameters              |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

<a id="6-system-administration-observability"></a><a id="6-system-administration--observability"></a>
## 6. System, Administration & Observability

⚙️ Appliance configuration, administrative profiles, API access, system schedules, logging, SNMP, and Sophos Fusion.

### <a id="administration"></a>`Administration`

Import: `from sfos_api import Administration`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Administration.ACCESS_PERMISSIONS`**<br><br>/administration/access/permissions | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Granular role-based access control permissions                     |
| **`Administration.ACCESS_PROFILES`**<br><br>/administration/access/profiles | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*                                                                                                             | Administrator privilege profiles (Read/Write/None)                 |
| **`Administration.API_SETTINGS`**<br><br>/administration/api-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | SFOS WebAdmin REST API access, allowed IPs, and API client status  |
| **`Administration.MESSAGES`**<br><br>/administration/messages | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Custom administrator login and legal disclaimer banners            |
| **`Administration.PORTAL_SETTINGS`**<br><br>/administration/portal-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | WebAdmin and User Portal listening ports and protocols             |
| **`Administration.SCHEDULES`**<br><br>/administration/schedules | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`, `page`, `pageSize`, `pageTotal`                                                                 | Time periods (one-time and recurring) for policy rules             |
| **`Administration.SUPPORT_ACCESS`**<br><br>/administration/support-access | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Sophos technical support secure reverse-SSH tunnel                 |
| **`Administration.SYSTEM_SETTINGS`**<br><br>/administration/system-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Hostname, time zone, NTP servers, and language settings            |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="logging"></a>`Logging`

Import: `from sfos_api import Logging`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Logging.LOG_ATTRIBUTES_COMPONENTS`**<br><br>/logging/log-attributes/components | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Logging subsystem components (Firewall, IPS, Web, VPN)             |
| **`Logging.LOG_ATTRIBUTES_TYPES`**<br><br>/logging/log-attributes/types | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Log severity levels and message categories                         |
| **`Logging.LOG_DESTINATIONS_CENTRAL_FIREWALL_REPORTING`**<br><br>/logging/log-destinations/central-firewall-reporting | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Sophos Fusion Cloud Firewall Reporting forwarding                 |
| **`Logging.LOG_DESTINATIONS_LOG_VIEWER`**<br><br>/logging/log-destinations/log-viewer | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Local Log Viewer retention and query settings                      |
| **`Logging.LOG_DESTINATIONS_SYSLOG_SERVERS`**<br><br>/logging/log-destinations/syslog-servers | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*<br>Query: `nameContains`, `nameNotEquals`                                                                 | Remote Syslog SIEM targets (UDP/TCP/TLS)                           |
| **`Logging.LOG_DESTINATIONS_SYSLOG_SERVERS_BY_ID_OR_NAME_LOGS`**<br><br>/logging/log-destinations/syslog-servers/{idOrName}/logs | `GET`<br>`PATCH` | `client.get(endpoint, id_or_name)`<br>`client.patch(endpoint, id_or_name, data=data)` | Path: `idOrName` *(required)*                                                                                                           | Facility and log category filters per Syslog server                |
| **`Logging.LOG_SETTINGS`**<br><br>/logging/log-settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Global log buffer sizes and local disk archiving policies          |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="monitoring"></a>`Monitoring`

Import: `from sfos_api import Monitoring`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Monitoring.NETFLOW_COLLECTORS`**<br><br>/monitoring/netflow/collectors | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*                                                                                                             | NetFlow / IPFIX flow export collectors and sampling rates          |
| **`Monitoring.SNMP_AGENT_CONFIGURATION`**<br><br>/monitoring/snmp/agent-configuration | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | SNMPv1/v2c/v3 agent listener configuration                         |
| **`Monitoring.SNMP_COMMUNITIES`**<br><br>/monitoring/snmp/communities | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*                                                                                                             | SNMPv1/v2c community strings and permitted source hosts            |
| **`Monitoring.SNMP_USERS`**<br><br>/monitoring/snmp/users | `GET`<br>`POST`<br>`PATCH`<br>`DELETE` | `client.get(endpoint, [id_or_name])`<br>`client.post(endpoint, data)`<br>`client.patch(endpoint, id_or_name, data=data)`<br>`client.delete(endpoint, id_or_name)` | Path: `id_or_name` *(item)*                                                                                                             | SNMPv3 USM user accounts, authentication, and privacy keys         |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="notification"></a>`Notification`

Import: `from sfos_api import Notification`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`Notification.NOTIFICATIONS`**<br><br>/notification/notifications | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Email notifications, SMTP mail server, and alert recipients        |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

### <a id="system"></a>`System`

Import: `from sfos_api import System`

| Endpoint | Supported Methods | Method Signatures | Parameters                                                                                                                              | Description                                                        |
| --- | :--- | :--- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| **`System.BACKUP_SETTINGS`**<br><br>/system/backup/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Scheduled automated backup settings (FTP/Email/Local)              |
| **`System.HOTFIX_SETTINGS`**<br><br>/system/hotfix/settings | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Automatic hotfix and critical patch installation policy            |
| **`System.PATTERN_UPDATES_SETTINGS`**<br><br>/system/pattern-updates/settings | `GET`<br>`PATCH` | `client.get(endpoint)`<br>`client.patch(endpoint, data=data)` | Body: JSON payload                                                                                                                      | Threat intelligence and pattern update schedules                   |
| **`System.SECURITY_UPDATES`**<br><br>/system/security-updates | `GET` | `client.get(endpoint)` | None *(singleton)*                                                                                                                      | Available firmware upgrades and security release status            |

[↑ Back to Table of Domains](#table-of-domains) &nbsp;•&nbsp; [↑ Back to Top](#top)

---

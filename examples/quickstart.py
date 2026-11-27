"""End-to-end quickstart demonstration for sfos_api.

Demonstrates:
- Client initialization and context management
- Domain-scoped StrEnum endpoints (Network, Firewall, Authentication)
- Full CRUD lifecycle on an IPv4 host object (create, read, update, delete)
- Creating two IPv4 firewall rules and exchanging their rulebase positions (move)
- Filtered collection reads and batch rule cleanup (delete)
- Service connectivity diagnostics (test_connection)
- Structured error handling

Requirements:
- `.credentials/config.ini` configured with a `[firewall]` section (`host`, `api_key`)
- `sfos-api` and `utils-api` installed (`pip install -e ".[examples]"`)
"""

from __future__ import annotations

import sys

from utils_api import find_credentials_file, load_ini_profile, print_data

from sfos_api import (
    Authentication,
    Firewall,
    Network,
    SFOSClient,
    parse_error,
)


def handle_example_error(e: Exception, action_desc: str = "operation", resource_name: str | None = None) -> None:
    """Print an informative error message for quickstart operations."""
    info = parse_error(e)
    target = f" '{resource_name or info.resource_id}'" if (resource_name or info.resource_id) else ""
    print(f"Error during {action_desc}{target}: {info.message}")


def main() -> None:
    """Run the end-to-end SFOS REST API quickstart workflow."""
    print("==================================================")
    print(" Sophos Firewall OS (SFOS) REST API - Quickstart")
    print(" Using StrEnum Domain Classes")
    print("==================================================\n")

    try:
        config_path = find_credentials_file(start_dir=__file__)
        client = SFOSClient(config_path=config_path)
    except Exception as e:
        print(f"Configuration error: {e}")
        print("Please ensure .credentials/config.ini contains a [firewall] section with host and api_key.")
        sys.exit(1)

    test_host = {
        "name": "Demo_Host_Light",
        "type": "ipv4Address",
        "ipv4Address": "198.51.100.42",
    }
    allow_rule_name = "demo-rule-allow-http"
    drop_rule_name = "demo-rule-drop-telnet"

    allow_rule_payload = {
        "name": allow_rule_name,
        "description": "Quickstart demo allow HTTP/HTTPS rule",
        "ruleType": "firewall",
        "enabled": False,
        "action": "accept",
        "position": "top",
        "sourceZones": {"any": True},
        "sourceNetworks": {
            "ipv4Addresses": [{"name": test_host["name"]}],
        },
        "destinationZones": {"any": True},
        "destinationNetworks": {"any": True},
        "servicesOrGroups": {
            "services": [
                {"name": "HTTP"},
                {"name": "HTTPS"},
            ],
        },
        "logTraffic": True,
    }

    drop_rule_payload = {
        "name": drop_rule_name,
        "description": "Quickstart demo drop Telnet rule",
        "ruleType": "firewall",
        "enabled": False,
        "action": "drop",
        "position": "after",
        "referenceItem": {"name": allow_rule_name},
        "sourceZones": {"any": True},
        "sourceNetworks": {"any": True},
        "destinationZones": {"any": True},
        "destinationNetworks": {"any": True},
        "servicesOrGroups": {
            "services": [{"name": "TELNET"}],
        },
        "logTraffic": True,
    }

    with client:
        # 1. READ COLLECTION (Auto-paginated)
        print("1. Reading network zones...")
        try:
            zones = client.get(Network.ZONES)
            print("Successfully retrieved zones:")
            print_data(zones.get("items", []), include=["name", "type", "description"])
        except Exception as e:
            handle_example_error(e, "reading network zones")

        # 2. CREATE IPv4 HOST RESOURCE
        print(f"\n2. Creating IPv4 host object '{test_host['name']}'...")
        try:
            res = client.post(Network.ADDRESSES_IPV4, test_host)
            print("Host created:")
            print_data(res)
        except Exception as e:
            handle_example_error(e, "creating host object", test_host["name"])

        # 3. READ & UPDATE IPv4 HOST RESOURCE (JSON Merge Patch)
        print(f"\n3. Reading and updating host object '{test_host['name']}'...")
        try:
            client.patch(
                Network.ADDRESSES_IPV4,
                test_host["name"],
                data={"description": "Provisioned via sfos_api quickstart"},
            )
            host_info = client.get(Network.ADDRESSES_IPV4, test_host["name"])
            print("Updated host details:")
            print_data(host_info)
        except Exception as e:
            handle_example_error(e, "updating host object", test_host["name"])

        # 4. CREATE TWO IPv4 FIREWALL RULES
        print(f"\n4. Creating two IPv4 firewall rules ('{allow_rule_name}' and '{drop_rule_name}')...")
        try:
            client.post(Firewall.RULES_IPV4, allow_rule_payload)
            print(f"Created first rule: '{allow_rule_name}'")

            client.post(Firewall.RULES_IPV4, drop_rule_payload)
            print(f"Created second rule: '{drop_rule_name}' (placed after '{allow_rule_name}')")

            demo_rules = client.get(Firewall.RULES_IPV4, nameContains="demo-rule-")
            print("Initial demo rule order:")
            print_data(demo_rules.get("items", []), include=["name", "action", "enabled", "description"])
        except Exception as e:
            handle_example_error(e, "creating demo firewall rules")

        # 5. EXCHANGE FIREWALL RULE POSITIONS (move)
        print(f"\n5. Exchanging firewall rule positions (moving '{drop_rule_name}' before '{allow_rule_name}')...")
        try:
            client.move(
                Firewall.RULES_IPV4,
                {
                    "name": drop_rule_name,
                    "position": "before",
                    "referenceItem": {"name": allow_rule_name},
                },
            )
            print(f"Moved '{drop_rule_name}' before '{allow_rule_name}'.")

            swapped_rules = client.get(Firewall.RULES_IPV4, nameContains="demo-rule-")
            print("Rule order after exchange:")
            print_data(swapped_rules.get("items", []), include=["name", "action", "enabled", "description"])

            # Move back to original order (drop_rule after allow_rule)
            client.move(
                Firewall.RULES_IPV4,
                {
                    "name": drop_rule_name,
                    "position": "after",
                    "referenceItem": {"name": allow_rule_name},
                },
            )
            print(f"Restored '{drop_rule_name}' after '{allow_rule_name}'.")
        except Exception as e:
            handle_example_error(e, "exchanging firewall rule positions")

        # 6. SERVICE CONNECTIVITY TEST (test_connection)
        ad_password = load_ini_profile("firewall", config_path=config_path).get("ad_password")
        if ad_password:
            print("\n6. Testing Active Directory connection diagnostics...")
            try:
                test_res = client.test_connection(
                    Authentication.SERVERS_ACTIVE_DIRECTORY,
                    data={
                        "name": "AD",
                        "serverAddress": {"ipv4Address": "192.168.10.50"},
                        "connectionSecurity": "none",
                        "port": 389,
                        "netBIOSDomain": "sfos",
                        "adminUsername": "adread",
                        "password": ad_password,
                        "domainName": "sfos.local",
                        "searchQueries": ["dc=sfos,dc=local"],
                    },
                )
                print("Connection test result:")
                print_data(test_res)
            except Exception as e:
                handle_example_error(e, "testing Active Directory connection")
        else:
            print("\n6. Skipping Active Directory connection test; set ad_password in [firewall] of config.ini to enable it.")

        # 7. CLEANUP / DELETE DEMO RESOURCES
        print(f"\n7. Cleaning up demo firewall rules ('{allow_rule_name}', '{drop_rule_name}')...")
        try:
            del_rules = client.delete(Firewall.RULES_IPV4, items=[allow_rule_name, drop_rule_name])
            print("Demo firewall rules deleted:")
            print_data(del_rules)
        except Exception as e:
            handle_example_error(e, "deleting demo firewall rules")

        print(f"\n8. Deleting host object '{test_host['name']}'...")
        try:
            del_host = client.delete(Network.ADDRESSES_IPV4, test_host["name"])
            print("Host deleted:")
            print_data(del_host)
        except Exception as e:
            handle_example_error(e, "deleting host object", test_host["name"])

    print("\nQuickstart completed successfully!")


if __name__ == "__main__":
    main()

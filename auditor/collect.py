"""Read the subscription with the Azure SDK and return plain dicts for the checks."""

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource.resources import ResourceManagementClient  # moved in azure-mgmt-resource 25+
from azure.mgmt.storage import StorageManagementClient


def _rg(resource_id: str) -> str:
    parts = resource_id.split("/")
    return parts[4] if len(parts) > 4 else ""


def collect(subscription_id: str) -> dict:
    cred = DefaultAzureCredential()
    resources_client = ResourceManagementClient(cred, subscription_id)
    network = NetworkManagementClient(cred, subscription_id)
    compute = ComputeManagementClient(cred, subscription_id)
    storage = StorageManagementClient(cred, subscription_id)

    resources = [
        {"name": r.name, "type": r.type, "resource_group": _rg(r.id), "tags": r.tags}
        for r in resources_client.resources.list()
    ]
    # Resource groups are not returned by resources.list(), so add them.
    resources += [
        {"name": g.name, "type": "microsoft.resources/resourcegroups", "resource_group": g.name, "tags": g.tags}
        for g in resources_client.resource_groups.list()
    ]

    nsgs = []
    for nsg in network.network_security_groups.list_all():
        rules = []
        for rule in nsg.security_rules or []:
            sources = list(rule.source_address_prefixes or [])
            if rule.source_address_prefix:
                sources.append(rule.source_address_prefix)
            ports = list(rule.destination_port_ranges or [])
            if rule.destination_port_range:
                ports.append(rule.destination_port_range)
            rules.append(
                {"name": rule.name, "direction": rule.direction, "access": rule.access, "sources": sources, "ports": ports}
            )
        nsgs.append({"name": nsg.name, "resource_group": _rg(nsg.id), "rules": rules})

    public_ips = [
        {
            "name": ip.name,
            "resource_group": _rg(ip.id),
            "associated": bool(ip.ip_configuration or ip.nat_gateway),
        }
        for ip in network.public_ip_addresses.list_all()
    ]

    disks = [
        {"name": d.name, "resource_group": _rg(d.id), "managed_by": d.managed_by, "size_gb": d.disk_size_gb}
        for d in compute.disks.list()
    ]

    accounts = [
        {
            "name": a.name,
            "resource_group": _rg(a.id),
            "allow_blob_public_access": a.allow_blob_public_access,
            "https_only": a.enable_https_traffic_only,
            "min_tls": a.minimum_tls_version,
        }
        for a in storage.storage_accounts.list()
    ]

    return {"resources": resources, "nsgs": nsgs, "public_ips": public_ips, "disks": disks, "storage": accounts}

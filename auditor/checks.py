"""Pure checks. Each one takes plain dicts, so it can be tested without Azure."""

from .models import Finding

# Ports that should never be open to the whole internet.
RISKY_PORTS = {22: "SSH", 3389: "RDP", 445: "SMB", 1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL"}
INTERNET_SOURCES = {"*", "0.0.0.0/0", "internet", "any"}

# Resource types Azure creates by itself; asking for tags on them is noise.
IGNORED_TYPES = {"microsoft.network/networkwatchers"}


def check_tags(resources: list[dict], required: list[str]) -> list[Finding]:
    findings = []
    for r in resources:
        if r.get("type", "").lower() in IGNORED_TYPES:
            continue
        tags = {k.lower() for k in (r.get("tags") or {})}
        missing = [t for t in required if t.lower() not in tags]
        if missing:
            findings.append(
                Finding("missing-tags", "low", r["name"], r["resource_group"], "Missing tags: " + ", ".join(missing))
            )
    return findings


def port_in_range(spec: str, port: int) -> bool:
    spec = spec.strip()
    if spec == "*":
        return True
    if "-" in spec:
        low, high = spec.split("-", 1)
        return int(low) <= port <= int(high)
    return int(spec) == port


def check_nsg_rules(nsgs: list[dict]) -> list[Finding]:
    findings = []
    for nsg in nsgs:
        for rule in nsg.get("rules", []):
            if rule["direction"].lower() != "inbound" or rule["access"].lower() != "allow":
                continue
            if not any(s.lower() in INTERNET_SOURCES for s in rule["sources"]):
                continue
            if any(p.strip() == "*" for p in rule["ports"]):
                findings.append(
                    Finding(
                        "open-nsg-rule",
                        "high",
                        nsg["name"],
                        nsg["resource_group"],
                        f"Rule '{rule['name']}' allows the internet to reach every port",
                    )
                )
                continue
            for port, label in RISKY_PORTS.items():
                if any(port_in_range(p, port) for p in rule["ports"]):
                    findings.append(
                        Finding(
                            "open-nsg-rule",
                            "high",
                            nsg["name"],
                            nsg["resource_group"],
                            f"Rule '{rule['name']}' allows the internet to reach {label} (port {port})",
                        )
                    )
    return findings


def check_storage(accounts: list[dict]) -> list[Finding]:
    findings = []
    for a in accounts:
        if a.get("allow_blob_public_access"):
            findings.append(
                Finding("storage-public-access", "high", a["name"], a["resource_group"], "Blobs can be made public")
            )
        if not a.get("https_only", True):
            findings.append(
                Finding("storage-no-https", "medium", a["name"], a["resource_group"], "HTTP traffic is allowed")
            )
        if a.get("min_tls") in ("TLS1_0", "TLS1_1"):
            findings.append(
                Finding("storage-old-tls", "medium", a["name"], a["resource_group"], f"Minimum TLS is {a['min_tls']}")
            )
    return findings


def check_disks(disks: list[dict]) -> list[Finding]:
    return [
        Finding(
            "unattached-disk",
            "medium",
            d["name"],
            d["resource_group"],
            f"{d.get('size_gb', '?')} GB disk is not attached to any VM and still costs money",
        )
        for d in disks
        if not d.get("managed_by")
    ]


def check_public_ips(ips: list[dict]) -> list[Finding]:
    return [
        Finding(
            "unused-public-ip",
            "medium",
            ip["name"],
            ip["resource_group"],
            "Public IP is not associated with anything and is billed",
        )
        for ip in ips
        if not ip.get("associated")
    ]

from auditor import checks


def test_missing_tags_are_reported():
    resources = [
        {"name": "a", "type": "x", "resource_group": "rg", "tags": {"Environment": "dev"}},
        {"name": "b", "type": "x", "resource_group": "rg", "tags": None},
    ]
    found = checks.check_tags(resources, ["environment", "project"])
    assert [f.resource for f in found] == ["a", "b"]
    assert "project" in found[0].detail and "environment" not in found[0].detail


def test_network_watcher_is_ignored():
    resources = [{"name": "nw", "type": "Microsoft.Network/networkWatchers", "resource_group": "rg", "tags": None}]
    assert checks.check_tags(resources, ["project"]) == []


def nsg(**rule):
    base = {"name": "r", "direction": "Inbound", "access": "Allow", "sources": ["*"], "ports": ["22"]}
    base.update(rule)
    return [{"name": "nsg1", "resource_group": "rg", "rules": [base]}]


def test_ssh_open_to_internet_is_high():
    found = checks.check_nsg_rules(nsg())
    assert len(found) == 1 and found[0].severity == "high" and "SSH" in found[0].detail


def test_port_range_covering_rdp_is_found():
    found = checks.check_nsg_rules(nsg(ports=["3000-4000"]))
    assert any("RDP" in f.detail for f in found)


def test_any_port_is_reported_once():
    found = checks.check_nsg_rules(nsg(ports=["*"]))
    assert len(found) == 1 and "every port" in found[0].detail


def test_deny_outbound_and_private_sources_are_fine():
    assert checks.check_nsg_rules(nsg(access="Deny")) == []
    assert checks.check_nsg_rules(nsg(direction="Outbound")) == []
    assert checks.check_nsg_rules(nsg(sources=["10.0.0.0/16"])) == []


def test_storage_findings():
    accounts = [
        {"name": "bad", "resource_group": "rg", "allow_blob_public_access": True, "https_only": False, "min_tls": "TLS1_0"},
        {"name": "good", "resource_group": "rg", "allow_blob_public_access": False, "https_only": True, "min_tls": "TLS1_2"},
    ]
    found = checks.check_storage(accounts)
    assert {f.check for f in found} == {"storage-public-access", "storage-no-https", "storage-old-tls"}
    assert all(f.resource == "bad" for f in found)


def test_unattached_disk_and_unused_ip():
    disks = [
        {"name": "d1", "resource_group": "rg", "managed_by": None, "size_gb": 128},
        {"name": "d2", "resource_group": "rg", "managed_by": "/subscriptions/x/vm", "size_gb": 128},
    ]
    ips = [
        {"name": "ip1", "resource_group": "rg", "associated": False},
        {"name": "ip2", "resource_group": "rg", "associated": True},
    ]
    assert [f.resource for f in checks.check_disks(disks)] == ["d1"]
    assert [f.resource for f in checks.check_public_ips(ips)] == ["ip1"]

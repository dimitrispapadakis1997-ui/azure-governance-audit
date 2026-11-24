# Azure Governance & Cost Audit

A Python tool that audits an Azure subscription and writes a Markdown and JSON report. It looks for the things that quietly cost money or open security holes. It runs from GitHub Actions on every push and every Monday, signs in with OIDC (no stored secrets) and only reads from Azure.

**Status:** 🚧 In progress. See [docs/progress-log.md](docs/progress-log.md).

## What it checks

| Check | Severity | What it finds |
|---|---|---|
| `open-nsg-rule` | high | An inbound rule that lets the internet reach every port, or SSH, RDP, SMB, SQL Server, MySQL or PostgreSQL |
| `storage-public-access` | high | Storage accounts where blobs can be made public |
| `storage-no-https` / `storage-old-tls` | medium | Storage accounts that allow HTTP or TLS 1.0/1.1 |
| `unattached-disk` | medium | Managed disks not attached to any VM, which are still billed |
| `unused-public-ip` | medium | Public IPs not associated with anything, which are billed |
| `missing-tags` | low | Resources and resource groups without the required tags (`environment`, `project` by default) |

## How it is built

- `auditor/collect.py` reads the subscription with the Azure SDK and returns plain dicts.
- `auditor/checks.py` holds the checks as pure functions over those dicts, so they are tested without Azure (`tests/`).
- `auditor/report.py` writes the report. `auditor/cli.py` ties it together.

```
python -m auditor --subscription <id> --out report
python -m auditor --subscription <id> --fail-on-high   # exit 1 on a high finding
```

Sign in first (for example with `az login`); the tool uses `DefaultAzureCredential`.

## Pipeline

`.github/workflows/audit.yml` runs the unit tests on every push and pull request. On `main` and on the weekly schedule it also signs in with OIDC, runs the audit, shows the report in the run summary and uploads it as an artifact. Setup is in [docs/bootstrap.md](docs/bootstrap.md).

## How this was built

I built this with an AI assistant (Claude) to speed up writing code and documentation. I chose what to check and why, set up the authentication, ran the audit against my own subscription and reviewed the results. The progress log records the problems that came up and how they were fixed.

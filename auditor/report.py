import json
from collections import Counter
from datetime import datetime, timezone

from .models import SEVERITIES, Finding


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2)


def to_markdown(findings: list[Finding], scanned: dict) -> str:
    counts = Counter(f.severity for f in findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Azure audit report",
        "",
        f"Generated {now}.",
        "",
        "## Scanned",
        "",
        "| Resource type | Count |",
        "|---|---|",
    ]
    lines += [f"| {name} | {count} |" for name, count in scanned.items()]
    lines += ["", "## Summary", "", "| Severity | Findings |", "|---|---|"]
    lines += [f"| {s} | {counts.get(s, 0)} |" for s in SEVERITIES]
    lines.append("")

    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    lines += ["## Findings", "", "| Severity | Check | Resource | Resource group | Detail |", "|---|---|---|---|---|"]
    order = {s: i for i, s in enumerate(SEVERITIES)}
    for f in sorted(findings, key=lambda x: (order[x.severity], x.check, x.resource)):
        lines.append(f"| {f.severity} | {f.check} | {f.resource} | {f.resource_group} | {f.detail} |")
    return "\n".join(lines) + "\n"

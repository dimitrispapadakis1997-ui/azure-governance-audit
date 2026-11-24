import argparse
import sys
from pathlib import Path

from . import checks
from .collect import collect
from .report import to_json, to_markdown


def run_checks(data: dict, required_tags: list[str]) -> list:
    return (
        checks.check_tags(data["resources"], required_tags)
        + checks.check_nsg_rules(data["nsgs"])
        + checks.check_storage(data["storage"])
        + checks.check_disks(data["disks"])
        + checks.check_public_ips(data["public_ips"])
    )


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Audit an Azure subscription.")
    p.add_argument("--subscription", required=True, help="Subscription ID")
    p.add_argument("--required-tags", default="environment,project", help="Comma separated tag names")
    p.add_argument("--out", default="report", help="Output directory")
    p.add_argument("--fail-on-high", action="store_true", help="Exit with 1 if there is a high severity finding")
    args = p.parse_args(argv)

    data = collect(args.subscription)
    findings = run_checks(data, [t.strip() for t in args.required_tags.split(",") if t.strip()])

    scanned = {
        "Resources and resource groups": len(data["resources"]),
        "Network security groups": len(data["nsgs"]),
        "Public IPs": len(data["public_ips"]),
        "Disks": len(data["disks"]),
        "Storage accounts": len(data["storage"]),
    }
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(to_markdown(findings, scanned), encoding="utf-8")
    (out / "report.json").write_text(to_json(findings), encoding="utf-8")
    print(f"{len(findings)} findings. Report written to {out}/")

    if args.fail_on_high and any(f.severity == "high" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

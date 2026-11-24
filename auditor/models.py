from dataclasses import dataclass, asdict

SEVERITIES = ("high", "medium", "low")


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    resource: str
    resource_group: str
    detail: str

    def to_dict(self) -> dict:
        return asdict(self)

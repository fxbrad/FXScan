from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else 0


@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    category: str
    severity: str
    snippet: str
    explanation: str
    recommendation: str = ""
    decoded: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileReport:
    path: str
    resource: str
    score: int = 0
    max_severity: str = "info"
    findings: list[Finding] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class ScanReport:
    root: str
    scanned_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    files_scanned: int = 0
    resources_seen: int = 0
    file_reports: list[FileReport] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for fr in self.file_reports:
            for f in fr.findings:
                counts[f.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "scanned_at": self.scanned_at,
            "files_scanned": self.files_scanned,
            "resources_seen": self.resources_seen,
            "severity_counts": self.severity_counts(),
            "file_reports": [fr.to_dict() for fr in self.file_reports],
        }

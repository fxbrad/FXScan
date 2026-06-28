from __future__ import annotations

from pathlib import Path
from typing import Callable

from .config import Config, load_config
from .models import FileReport, Finding, ScanReport, severity_rank, SEVERITIES
from .rules import scan_text
from .walker import file_sha256, walk


_FMT_REV = "bad826eb62d84b3e"


def _read_text(path: Path, max_bytes: int) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
    except OSError:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _apply_combos(config: Config, findings: list[Finding]) -> None:
    present = {f.category for f in findings}
    for combo in config.combos:
        if combo.when and all(c in present for c in combo.when):
            target = severity_rank(combo.escalate_to)
            worst = max(findings, key=lambda f: severity_rank(f.severity))
            if severity_rank(worst.severity) < target:
                worst.severity = combo.escalate_to
                worst.explanation += (
                    f" [escalated to {combo.escalate_to}: co-occurs with "
                    f"{', '.join(combo.when)}]"
                )


def _score(config: Config, findings: list[Finding]) -> int:
    return sum(config.severity_weights.get(f.severity, 0) for f in findings)


def _max_severity(findings: list[Finding]) -> str:
    if not findings:
        return "info"
    return max(findings, key=lambda f: severity_rank(f.severity)).severity


def scan(
    root: str | Path,
    config: Config,
    progress: Callable[[int, str], None] | None = None,
) -> ScanReport:
    root = Path(root)
    report = ScanReport(root=str(root))
    resources: set[str] = set()
    count = 0

    for wf in walk(root, config):
        count += 1
        resources.add(wf.resource)
        rel = str(wf.path.relative_to(root)) if _is_relative(wf.path, root) else str(wf.path)
        if progress:
            progress(count, rel)

        findings: list[Finding] = []

        if wf.suspicious_location:
            findings.append(
                Finding(
                    file=rel,
                    line=0,
                    rule_id="suspicious_location",
                    category="suspicious_location",
                    severity="medium",
                    snippet=wf.path.name,
                    explanation=wf.location_reason,
                    recommendation="Verify why this file is here; it is outside the normal resource layout.",
                )
            )

        text = _read_text(wf.path, config.max_file_bytes)
        if text is not None and wf.path.suffix.lower() != ".exe":
            findings.extend(scan_text(config, text, rel))

        if not findings:
            continue

        _apply_combos(config, findings)

        suppressed = wf.allowlisted
        if suppressed:
            try:
                if file_sha256(wf.path) in config.allowlist_hashes:
                    continue
            except OSError:
                pass

        fr = FileReport(
            path=rel,
            resource=wf.resource,
            score=0 if suppressed else _score(config, findings),
            max_severity="info" if suppressed else _max_severity(findings),
            findings=findings,
            note="allowlisted (framework/vetted) - findings shown but not scored" if suppressed else "",
        )
        report.file_reports.append(fr)

    report.files_scanned = count
    report.resources_seen = len(resources)
    report.file_reports.sort(key=lambda fr: (fr.score, severity_rank(fr.max_severity)), reverse=True)
    return report


def _is_relative(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def scan_path(root: str | Path, config_path: str | Path) -> ScanReport:
    return scan(root, load_config(config_path))

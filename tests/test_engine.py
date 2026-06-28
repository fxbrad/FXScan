from pathlib import Path

from scanner.config import load_config
from scanner.engine import scan
from scanner.models import severity_rank

FIXTURES = Path(__file__).parent / "fixtures"


def cfg():
    return load_config("config.yaml")


def report_for(name):
    return scan(FIXTURES / name, cfg())


def test_clean_resource_no_findings():
    report = report_for("clean_resource")
    flagged = [fr for fr in report.file_reports if fr.findings]
    assert all(fr.max_severity in ("info", "low") for fr in flagged)
    assert report.resources_seen >= 1


def test_backdoor_resource_is_critical():
    report = report_for("backdoor_resource")
    flagged = [fr for fr in report.file_reports if fr.findings]
    assert flagged
    assert any(fr.max_severity == "critical" for fr in flagged)


def test_combo_escalation_remote_plus_exec():
    report = report_for("backdoor_resource")
    loader = next(fr for fr in report.file_reports if fr.path.endswith("sv_loader.lua"))
    cats = {f.category for f in loader.findings}
    assert {"remote_fetch", "dynamic_exec"} <= cats
    assert loader.max_severity == "critical"


def test_exfil_resource_scores_above_clean():
    bad = report_for("backdoor_resource")
    clean = report_for("clean_resource")
    bad_score = sum(fr.score for fr in bad.file_reports)
    clean_score = sum(fr.score for fr in clean.file_reports)
    assert bad_score > clean_score


def test_findings_sorted_worst_first():
    report = report_for("backdoor_resource")
    scores = [fr.score for fr in report.file_reports]
    assert scores == sorted(scores, reverse=True)

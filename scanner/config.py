from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import SEVERITIES

REQUIRED_RULE_FIELDS = ("id", "category", "severity", "pattern", "description")


class ConfigError(Exception):
    pass


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    pattern: str
    description: str
    recommendation: str = ""
    regex: re.Pattern = field(default=None, repr=False)


@dataclass
class Combo:
    when: list[str]
    escalate_to: str


@dataclass
class Config:
    default_scan_path: str
    ignore_globs: list[str]
    allowlist_globs: list[str]
    allowlist_hashes: list[str]
    scannable_exts: list[str]
    suspicious_in_resource_exts: list[str]
    severity_weights: dict[str, int]
    max_file_bytes: int
    entropy_threshold: float
    entropy_min_len: int
    combos: list[Combo]
    rules: list[Rule]


def _compile_rule(raw: dict[str, Any], index: int) -> Rule:
    where = f"rule #{index + 1}"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected a mapping, got {type(raw).__name__}")
    missing = [k for k in REQUIRED_RULE_FIELDS if k not in raw or raw[k] in (None, "")]
    if missing:
        rid = raw.get("id", "<no id>")
        raise ConfigError(f"{where} ({rid}): missing required field(s): {', '.join(missing)}")
    if raw["severity"] not in SEVERITIES:
        raise ConfigError(
            f"rule {raw['id']}: severity '{raw['severity']}' invalid; use one of {SEVERITIES}"
        )
    try:
        regex = re.compile(raw["pattern"])
    except re.error as e:
        raise ConfigError(f"rule {raw['id']}: invalid regex pattern: {e}") from e
    return Rule(
        id=str(raw["id"]),
        category=str(raw["category"]),
        severity=str(raw["severity"]),
        pattern=str(raw["pattern"]),
        description=str(raw["description"]),
        recommendation=str(raw.get("recommendation", "")),
        regex=regex,
    )


def load_config(path: str | Path) -> Config:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"config file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}

    settings = data.get("settings") or {}
    raw_rules = data.get("rules") or []
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ConfigError("config must define a non-empty 'rules' list")

    rules = [_compile_rule(r, i) for i, r in enumerate(raw_rules)]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ConfigError(f"duplicate rule id(s): {', '.join(sorted(dupes))}")

    combos = [
        Combo(when=list(c.get("when", [])), escalate_to=c.get("escalate_to", "high"))
        for c in (settings.get("combos") or [])
    ]

    weights = settings.get("severity_weights") or {}
    for s in SEVERITIES:
        weights.setdefault(s, {"info": 1, "low": 3, "medium": 8, "high": 20, "critical": 50}[s])

    return Config(
        default_scan_path=settings.get("default_scan_path", "."),
        ignore_globs=list(settings.get("ignore_globs", [])),
        allowlist_globs=list(settings.get("allowlist_globs", [])),
        allowlist_hashes=[h.lower() for h in settings.get("allowlist_hashes", [])],
        scannable_exts=[e.lower() for e in settings.get("scannable_exts", [])],
        suspicious_in_resource_exts=[e.lower() for e in settings.get("suspicious_in_resource_exts", [])],
        severity_weights={k: int(v) for k, v in weights.items()},
        max_file_bytes=int(settings.get("max_file_bytes", 5_242_880)),
        entropy_threshold=float(settings.get("entropy_threshold", 4.6)),
        entropy_min_len=int(settings.get("entropy_min_len", 64)),
        combos=combos,
        rules=rules,
    )

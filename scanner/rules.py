from __future__ import annotations

from .config import Config, Rule
from .deobfuscate import decode_candidates, high_entropy_strings
from .models import Finding

ENTROPY_RULE_ID = "high_entropy_blob"
ENTROPY_CATEGORY = "obfuscation"


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet(text: str, pos: int, width: int = 160) -> str:
    line_start = text.rfind("\n", 0, pos) + 1
    line_end = text.find("\n", pos)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].strip()
    return line[:width] + ("..." if len(line) > width else "")


def apply_rules(rules: list[Rule], text: str, file_label: str, decoded: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rule in rules:
        for m in rule.regex.finditer(text):
            findings.append(
                Finding(
                    file=file_label,
                    line=_line_of(text, m.start()),
                    rule_id=rule.id,
                    category=rule.category,
                    severity=rule.severity,
                    snippet=_snippet(text, m.start()),
                    explanation=rule.description,
                    recommendation=rule.recommendation,
                    decoded=decoded,
                )
            )
    return findings


def _looks_minified(text: str) -> bool:
    longest = max((len(line) for line in text.splitlines()), default=0)
    return longest > 1500


def scan_text(config: Config, text: str, file_label: str) -> list[Finding]:
    findings = apply_rules(config.rules, text, file_label)

    # Minified/bundled code (webpack output, vendored libs) produces overwhelming
    # entropy and base64 noise. Skip the heuristic layers there; the explicit
    # pattern rules above still run so a real payload is not missed.
    if _looks_minified(text):
        return findings

    for method, decoded in decode_candidates(text):
        sub = apply_rules(config.rules, decoded, file_label, decoded=decoded)
        for f in sub:
            f.explanation = f"{f.explanation} (found in {method}-decoded payload)"
        findings.extend(sub)

    for blob in high_entropy_strings(text, config.entropy_min_len, config.entropy_threshold):
        pos = text.find(blob)
        findings.append(
            Finding(
                file=file_label,
                line=_line_of(text, pos) if pos >= 0 else 0,
                rule_id=ENTROPY_RULE_ID,
                category=ENTROPY_CATEGORY,
                severity="medium",
                snippet=blob[:120] + ("..." if len(blob) > 120 else ""),
                explanation="High-entropy string literal (likely packed or encrypted data)",
                recommendation="Inspect what this opaque blob decodes to and how it is used.",
            )
        )

    return findings

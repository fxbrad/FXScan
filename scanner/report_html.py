from __future__ import annotations

import html

from ._meta import encode_zero_width, fingerprint
from .models import ScanReport, SEVERITIES

_SEV_COLOR = {
    "info": "#6b7280",
    "low": "#2563eb",
    "medium": "#d97706",
    "high": "#dc2626",
    "critical": "#7f1d1d",
}

_CSS = """
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       color: #1f2937; margin: 0; padding: 24px; background: #f9fafb; font-size: 14px; }
h1 { font-size: 20px; margin: 0 0 4px; }
.meta { color: #6b7280; margin-bottom: 20px; }
.cards { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 24px; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px;
        padding: 10px 14px; min-width: 90px; }
.card .n { font-size: 22px; font-weight: 600; }
.card .l { color: #6b7280; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.file { background: #fff; border: 1px solid #e5e7eb; border-radius: 6px;
        margin-bottom: 14px; overflow: hidden; }
.file > header { padding: 10px 14px; border-bottom: 1px solid #e5e7eb;
                 display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.file h2 { font-size: 14px; margin: 0; font-family: ui-monospace, Consolas, monospace; word-break: break-all; }
.file .res { color: #6b7280; font-size: 12px; }
.note { color: #6b7280; font-style: italic; font-size: 12px; }
table { width: 100%; border-collapse: collapse; }
td, th { text-align: left; padding: 7px 14px; border-top: 1px solid #f3f4f6; vertical-align: top; }
th { color: #6b7280; font-size: 12px; font-weight: 600; }
.dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; }
.sev { font-weight: 600; white-space: nowrap; }
code { font-family: ui-monospace, Consolas, monospace; background: #f3f4f6;
       padding: 1px 4px; border-radius: 3px; white-space: pre-wrap; word-break: break-all; }
.decoded { color: #7f1d1d; margin-top: 4px; display: block; }
.watermark { position: fixed; bottom: 12px; right: 14px; font-size: 12px; color: #9ca3af;
             background: rgba(255,255,255,.9); border: 1px solid #e5e7eb; padding: 5px 11px;
             border-radius: 999px; box-shadow: 0 1px 2px rgba(0,0,0,.05); }
.watermark a { color: #6b7280; font-weight: 600; }
.watermark a:hover { color: #5865f2; }
"""

_WATERMARK = (
    '<div class="watermark">Join the '
    '<a href="https://discord.gg/x5avNnbEJT" target="_blank" rel="noopener">Discord</a>'
    ' for support + updates</div>'
)


def _badge(severity: str) -> str:
    color = _SEV_COLOR.get(severity, "#6b7280")
    return f'<span class="sev"><span class="dot" style="background:{color}"></span>{severity}</span>'


def render(report: ScanReport) -> str:
    counts = report.severity_counts()
    cards = "".join(
        f'<div class="card"><div class="n" style="color:{_SEV_COLOR[s]}">{counts[s]}</div>'
        f'<div class="l">{s}</div></div>'
        for s in reversed(SEVERITIES)
    )
    cards = (
        f'<div class="card"><div class="n">{report.files_scanned}</div><div class="l">files</div></div>'
        f'<div class="card"><div class="n">{report.resources_seen}</div><div class="l">resources</div></div>'
        + cards
    )

    flagged = [fr for fr in report.file_reports if fr.findings]
    blocks = []
    for fr in flagged:
        rows = []
        for f in sorted(fr.findings, key=lambda x: -SEVERITIES.index(x.severity)):
            decoded = ""
            if f.decoded:
                d = html.escape(f.decoded[:300])
                decoded = f'<code class="decoded">decoded: {d}</code>'
            rows.append(
                f"<tr><td>{_badge(f.severity)}</td>"
                f"<td>{html.escape(f.category)}<br><span class='res'>{html.escape(f.rule_id)}</span></td>"
                f"<td>{f.line or ''}</td>"
                f"<td>{html.escape(f.explanation)}<br><code>{html.escape(f.snippet)}</code>{decoded}"
                f"<br><span class='note'>{html.escape(f.recommendation)}</span></td></tr>"
            )
        note = f'<span class="note">{html.escape(fr.note)}</span>' if fr.note else ""
        blocks.append(
            f'<div class="file"><header><div><h2>{html.escape(fr.path)}</h2>'
            f'<span class="res">{html.escape(fr.resource)}</span></div>'
            f'<div style="text-align:right">{_badge(fr.max_severity)}<br>'
            f'<span class="res">score {fr.score}</span> {note}</div></header>'
            f"<table><thead><tr><th>Severity</th><th>Category</th><th>Line</th><th>Detail</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>"
        )

    if not blocks:
        blocks.append('<p class="note">No findings.</p>')

    fp = fingerprint()
    zw = encode_zero_width(fp)
    return (
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<!-- build:{fp} -->"
        f"<title>FXScan - {html.escape(report.root)}</title><style>{_CSS}</style></head><body>"
        f"<h1>FXScan{zw}</h1>"
        f"<div class='meta'>{html.escape(report.root)} · {report.scanned_at}</div>"
        f"<div class='cards'>{cards}</div>"
        f"{''.join(blocks)}{_WATERMARK}</body></html>"
    )

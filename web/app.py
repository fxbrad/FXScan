from __future__ import annotations

import sys
import uuid
from pathlib import Path

from flask import Flask, Response, abort, redirect, render_template, request, url_for

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner._meta import build_id, fingerprint
from scanner.config import ConfigError, load_config
from scanner.engine import scan
from scanner.models import SEVERITIES
from scanner.report_html import render as render_report

BASE = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE / "config.yaml"

app = Flask(__name__)
_reports: dict[str, object] = {}


@app.route("/")
def index():
    try:
        cfg = load_config(CONFIG_PATH)
        default_path = cfg.default_scan_path
        error = None
    except ConfigError as e:
        default_path = ""
        error = str(e)
    return render_template("index.html", default_path=default_path, error=error)


@app.route("/scan", methods=["POST"])
def run_scan():
    target = (request.form.get("path") or "").strip()
    if not target or not Path(target).exists():
        return render_template(
            "index.html", default_path=target, error=f"Path not found: {target}"
        )
    try:
        cfg = load_config(CONFIG_PATH)
    except ConfigError as e:
        return render_template("index.html", default_path=target, error=str(e))

    report = scan(target, cfg, progress=lambda n, f: print(f"[{n}] {f}"))
    scan_id = uuid.uuid4().hex[:12]
    _reports[scan_id] = report
    return redirect(url_for("results", scan_id=scan_id))


@app.route("/results/<scan_id>")
def results(scan_id: str):
    report = _reports.get(scan_id)
    if report is None:
        abort(404)
    return render_template(
        "results.html",
        scan_id=scan_id,
        report=report,
        counts=report.severity_counts(),
        severities=SEVERITIES,
        flagged=[fr for fr in report.file_reports if fr.findings],
    )


@app.route("/report/<scan_id>.html")
def report_html(scan_id: str):
    report = _reports.get(scan_id)
    if report is None:
        abort(404)
    return Response(
        render_report(report),
        mimetype="text/html",
        headers={"Content-Disposition": f'attachment; filename="fxscan-{scan_id}.html"'},
    )


@app.route("/.well-known/build")
def build_info():
    return {"build": fingerprint(), "id": build_id()}


if __name__ == "__main__":
    print("FXScan running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000)

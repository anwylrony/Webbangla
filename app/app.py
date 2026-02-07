from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

from flask import Flask, render_template, request

from scanner.report import build_report
from scanner.scanner import run_scan

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.get("/")
def index() -> str:
    return render_template("index.html")


@app.post("/scan")
def scan() -> str:
    target = request.form.get("target", "").strip()
    safe_mode = request.form.get("safe_mode") == "on"
    if not target:
        return render_template(
            "index.html",
            error="Target is required. Provide a domain, URL, IP, or CIDR.",
        )

    scan_result = run_scan(target=target, safe_mode=safe_mode)
    report = build_report(scan_result)

    report_json = json.dumps(report, indent=2)
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    report_path = BASE_DIR / "reports" / f"report-{timestamp}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_json, encoding="utf-8")

    return render_template(
        "report.html",
        target=target,
        report=report,
        report_json=report_json,
        report_path=report_path.relative_to(BASE_DIR),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)

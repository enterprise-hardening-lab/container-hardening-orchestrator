#!/usr/bin/env python3
# Path: orchestrator/generate_html_report.py

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

TRIVY_JSON = Path("reports/generated/trivy-scan.json")
SEMGREP_SARIF = Path("reports/generated/semgrep-report.sarif")
OUT_DIR = Path("reports/final")
OUT_HTML = OUT_DIR / "security-summary.html"
OUT_JSON = OUT_DIR / "security-summary.json"

def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None

def summarize_trivy(trivy: Dict[str, Any]) -> Dict[str, Any]:
    """Return counts by severity from Trivy JSON."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "total": 0}
    if not trivy:
        return summary

    results = trivy if isinstance(trivy, list) else trivy.get("Results") or trivy.get("results") or []
    # Trivy may produce a dict with Results, or a plain list; handle both
    if isinstance(results, dict):
        results = results.get("Results", [])

    for r in results or []:
        vulns = r.get("Vulnerabilities") or r.get("vulnerabilities") or []
        for v in vulns:
            sev = str(v.get("Severity", "UNKNOWN")).upper()
            if sev not in summary:
                sev = "UNKNOWN"
            summary[sev] += 1
            summary["total"] += 1
    return summary

def summarize_semgrep(sarif: Dict[str, Any]) -> Dict[str, Any]:
    """Return counts by severity from SARIF."""
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 0}
    if not sarif:
        return summary

    runs = sarif.get("runs", [])
    for run in runs:
        results = run.get("results", [])
        for res in results:
            level = (res.get("level") or "warning").lower()
            # Map SARIF levels to severities
            if level in ("error",):
                sev = "HIGH"
            elif level in ("warning",):
                sev = "MEDIUM"
            elif level in ("note", "information", "info"):
                sev = "LOW"
            else:
                sev = "INFO"
            summary[sev] += 1
            summary["total"] += 1
    return summary

def html_row(label: str, v: int) -> str:
    return f"<tr><td>{label}</td><td style='text-align:right;'>{v}</td></tr>"

def render_html(app_name: str, base_image: str, trivy_sum: Dict[str, int], semgrep_sum: Dict[str, int]) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Security Summary — {app_name}</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 24px; color: #111; }}
  .card {{ border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
  h1 {{ margin: 0 0 6px 0; font-size: 24px; }}
  h2 {{ margin: 0 0 12px 0; font-size: 18px; }}
  .meta {{ color:#6b7280; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 8px 6px; border-bottom: 1px solid #f3f4f6; }}
  th {{ text-align: left; color:#374151; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; }}
  .pill {{ display:inline-block; padding:4px 10px; border-radius:999px; font-size:12px; margin-left:6px; background:#f3f4f6; }}
</style>
</head>
<body>
  <div class="card">
    <h1>Security Summary</h1>
    <div class="meta">Generated: {now}</div>
    <div class="meta">Application: <strong>{app_name}</strong> &nbsp;|&nbsp; Base Image: <strong>{base_image}</strong></div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Container Image (Trivy)
        <span class="pill">Total: {trivy_sum.get('total', 0)}</span>
      </h2>
      <table>
        <thead><tr><th>Severity</th><th style="text-align:right;">Count</th></tr></thead>
        <tbody>
          {html_row('CRITICAL', trivy_sum.get('CRITICAL', 0))}
          {html_row('HIGH', trivy_sum.get('HIGH', 0))}
          {html_row('MEDIUM', trivy_sum.get('MEDIUM', 0))}
          {html_row('LOW', trivy_sum.get('LOW', 0))}
          {html_row('UNKNOWN', trivy_sum.get('UNKNOWN', 0))}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h2>Application Code (Semgrep)
        <span class="pill">Total: {semgrep_sum.get('total', 0)}</span>
      </h2>
      <table>
        <thead><tr><th>Severity</th><th style="text-align:right;">Count</th></tr></thead>
        <tbody>
          {html_row('CRITICAL', semgrep_sum.get('CRITICAL', 0))}
          {html_row('HIGH', semgrep_sum.get('HIGH', 0))}
          {html_row('MEDIUM', semgrep_sum.get('MEDIUM', 0))}
          {html_row('LOW', semgrep_sum.get('LOW', 0))}
          {html_row('INFO', semgrep_sum.get('INFO', 0))}
        </tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2>Notes</h2>
    <ul>
      <li>Counts are aggregated from Trivy JSON and Semgrep SARIF produced during this run.</li>
      <li>Use GitHub Security → Code scanning alerts for detailed Semgrep findings.</li>
      <li>Use raw Trivy JSON for per-package and CVE details.</li>
    </ul>
  </div>
</body>
</html>
"""

def main():
    # Inputs passed by workflow as environment variables (optional), else defaults:
    app_name = (Path(".env.app_name").read_text().strip() if Path(".env.app_name").exists() else "unknown-app")
    base_image = (Path(".env.base_image").read_text().strip() if Path(".env.base_image").exists() else "unknown")

    trivy = load_json(TRIVY_JSON)
    sarif = load_json(SEMGREP_SARIF)

    trivy_sum = summarize_trivy(trivy)
    semgrep_sum = summarize_semgrep(sarif)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps({
        "app_name": app_name,
        "base_image": base_image,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "trivy": trivy_sum,
        "semgrep": semgrep_sum
    }, indent=2))

    html = render_html(app_name, base_image, trivy_sum, semgrep_sum)
    OUT_HTML.write_text(html)

    print(f"✅ Wrote {OUT_HTML} and {OUT_JSON}")

if __name__ == "__main__":
    sys.exit(main())

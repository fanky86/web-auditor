"""Report generators: JSON, HTML, TXT."""
import os
import json
import html
import time
from datetime import datetime


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _ensure_dir(path="reports"):
    os.makedirs(path, exist_ok=True)
    return path


def write_all(ctx, out_dir="reports"):
    _ensure_dir(out_dir)
    duration = round(time.time() - ctx.start_time, 2)

    summary = {
        "target": ctx.target,
        "date": datetime.utcnow().isoformat() + "Z",
        "duration_seconds": duration,
        "pages_discovered": len(ctx.pages),
        "endpoints_discovered": len(ctx.endpoints),
        "api_endpoints_discovered": len(ctx.api_endpoints),
        "findings_total": len(ctx.findings),
        "requests_made": ctx.rl.count,
    }

    report = {
        "summary": summary,
        "findings": sorted(ctx.findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9)),
        "pages": [{"url": p["url"], "status": p["status"], "title": p["title"]}
                  for p in ctx.pages],
        "api_results": getattr(ctx, "api_results", []),
        "config": {k: v for k, v in ctx.config.items()
                   if k not in ("cookies", "cookie_file")},
    }

    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(os.path.join(out_dir, "endpoints.txt"), "w", encoding="utf-8") as f:
        for e in sorted(ctx.endpoints):
            f.write(e + "\n")

    with open(os.path.join(out_dir, "urls.txt"), "w", encoding="utf-8") as f:
        for p in ctx.pages:
            f.write(p["url"] + "\n")

    with open(os.path.join(out_dir, "findings.txt"), "w", encoding="utf-8") as f:
        for fnd in report["findings"]:
            f.write(f"[{fnd['severity']}] {fnd['title']}\n  URL: {fnd['url']}\n"
                    f"  Evidence: {fnd['evidence']}\n"
                    f"  Recommendation: {fnd['recommendation']}\n\n")

    html_path = os.path.join(out_dir, "report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_render_html(report))

    print(f"\n[REPORT] Written to {out_dir}/")
    print(f"  - report.json\n  - report.html\n  - endpoints.txt\n  - urls.txt\n  - findings.txt")
    return report


def _render_html(report):
    s = report["summary"]
    color = {"CRITICAL": "#8b0000", "HIGH": "#c0392b", "MEDIUM": "#e67e22",
             "LOW": "#27ae60", "INFO": "#2980b9"}
    rows = []
    for fnd in report["findings"]:
        c = color.get(fnd["severity"], "#555")
        rows.append(f"""
        <div class="finding" style="border-left:6px solid {c};">
          <div class="sev" style="color:{c}">[{html.escape(fnd['severity'])}] {html.escape(fnd['title'])}</div>
          <div><b>URL:</b> <code>{html.escape(fnd['url'])}</code></div>
          <div><b>Evidence:</b> {html.escape(fnd['evidence'])}</div>
          <div><b>Impact:</b> {html.escape(fnd['impact'])}</div>
          <div><b>Recommendation:</b> {html.escape(fnd['recommendation'])}</div>
        </div>""")

    pages_rows = "\n".join(
        f"<tr><td>{html.escape(p['url'])}</td><td>{p['status']}</td>"
        f"<td>{html.escape(p['title'])}</td></tr>" for p in report["pages"])
    api_rows = "\n".join(
        f"<tr><td><code>{html.escape(a['url'])}</code></td><td>{a.get('method')}</td>"
        f"<td>{a.get('status')}</td><td>{html.escape(str(a.get('content_type','')))}</td>"
        f"<td>{'Y' if a.get('auth_required') else ('N' if a.get('auth_required') is False else '?')}</td>"
        f"<td>{a.get('size')}</td></tr>" for a in report.get("api_results", []))

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Web Security Audit — {html.escape(s['target'])}</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color:#222; }}
 h1 {{ margin-bottom:0 }} .muted {{ color:#666 }}
 .card {{ background:#f7f7f9; border:1px solid #e1e1e6; padding:1rem 1.2rem;
          border-radius:8px; margin-bottom:1.5rem; }}
 .finding {{ padding:.8rem 1rem; background:#fff; border:1px solid #eee; margin:.6rem 0; border-radius:6px; }}
 .sev {{ font-weight:700; margin-bottom:.4rem; }}
 table {{ border-collapse:collapse; width:100%; font-size:.9rem; }}
 th,td {{ border:1px solid #ddd; padding:.4rem .6rem; text-align:left; }}
 th {{ background:#f0f0f3; }}
 code {{ background:#eef; padding:0 .25rem; border-radius:3px; }}
</style></head><body>
<h1>WEB SECURITY AUDIT</h1>
<p class="muted">Target: <b>{html.escape(s['target'])}</b><br>
Date: {html.escape(s['date'])} &middot; Duration: {s['duration_seconds']}s &middot;
Requests: {s['requests_made']}</p>

<div class="card">
  <h2>Summary</h2>
  <ul>
    <li>Pages discovered: <b>{s['pages_discovered']}</b></li>
    <li>Endpoints discovered: <b>{s['endpoints_discovered']}</b></li>
    <li>API endpoints: <b>{s['api_endpoints_discovered']}</b></li>
    <li>Total findings: <b>{s['findings_total']}</b></li>
  </ul>
</div>

<h2>Findings</h2>
{''.join(rows) or '<p>No findings.</p>'}

<h2>Pages</h2>
<table><thead><tr><th>URL</th><th>Status</th><th>Title</th></tr></thead>
<tbody>{pages_rows}</tbody></table>

<h2>API endpoints inspected</h2>
<table><thead><tr><th>URL</th><th>Method</th><th>Status</th><th>Content-Type</th>
<th>Auth required</th><th>Size</th></tr></thead>
<tbody>{api_rows or '<tr><td colspan="6">None</td></tr>'}</tbody></table>

<p class="muted" style="margin-top:2rem">
Report generated by WebSecurityAuditor — authorized self-audit only.
</p>
</body></html>"""

"""
HTML report generator for the RHEL 8 audit scanner.

Renders findings into a single self-contained dark-theme dashboard with a
severity summary, category breakdown, and per-finding cards that expand to
show description, affected items, remediation, and references. Every
user-controlled value is run through html.escape() to prevent injection
via config snippets that end up in affected_items.
"""

from __future__ import annotations

import datetime
import html
import json
from typing import Any, Dict, List

from . import __version__


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class ReportGenerator:
    def __init__(self, findings: List[Dict[str, Any]], meta: Dict[str, Any]):
        self.findings = findings
        self.meta = meta

    def generate(self, output_path: str) -> None:
        total = len(self.findings)
        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for f in self.findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1

        crit = by_sev.get("CRITICAL", 0)
        high = by_sev.get("HIGH", 0)
        med = by_sev.get("MEDIUM", 0)
        low = by_sev.get("LOW", 0)
        info = by_sev.get("INFO", 0)

        # Weighted risk score (0-100)
        risk_score = min(100, crit * 25 + high * 10 + med * 4 + low * 1)
        if risk_score >= 75:
            risk_label, risk_color = "Critical", "#ef4444"
        elif risk_score >= 40:
            risk_label, risk_color = "High", "#f97316"
        elif risk_score >= 15:
            risk_label, risk_color = "Medium", "#eab308"
        else:
            risk_label, risk_color = "Low", "#22c55e"

        cat_chart = json.dumps([
            {"name": k, "count": v}
            for k, v in sorted(by_cat.items(), key=lambda x: -x[1])
        ])

        body = self._render_findings()
        rendered = _TEMPLATE.format(
            version=html.escape(__version__),
            hostname=html.escape(self.meta.get("hostname", "unknown")),
            rhel=html.escape(self.meta.get("rhel_version") or "unknown"),
            kernel=html.escape(self.meta.get("kernel", "unknown")),
            collected=html.escape(self.meta.get("collected_at", "unknown")),
            generated=html.escape(datetime.datetime.now().isoformat(timespec="seconds")),
            modules=html.escape(", ".join(self.meta.get("modules_run", []))),
            bundle_source=html.escape(self.meta.get("bundle_source", "unknown")),
            total=total,
            crit=crit, high=high, med=med, low=low, info=info,
            risk_score=risk_score,
            risk_label=html.escape(risk_label),
            risk_color=risk_color,
            cat_chart=cat_chart,
            findings_html=body,
        )

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(rendered)

    # ---------------------------------------------------------- per-finding
    def _render_findings(self) -> str:
        if not self.findings:
            return '<div class="empty">No findings.</div>'
        ordered = sorted(
            self.findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f["severity"], 4),
                f["category"],
                f["check_id"],
            ),
        )
        parts: List[str] = []
        for f in ordered:
            sev = f["severity"]
            sev_cls = sev.lower()
            affected = ""
            if f.get("affected_items"):
                items = f["affected_items"][:50]
                items_html = "".join(
                    f"<li>{html.escape(str(item))}</li>" for item in items
                )
                if len(f["affected_items"]) > 50:
                    items_html += (
                        f"<li>… and {len(f['affected_items']) - 50} more</li>"
                    )
                affected = (
                    '<div class="sec"><div class="sec-h">Affected</div>'
                    f'<ul class="affected">{items_html}</ul></div>'
                )
            refs_html = ""
            if f.get("references"):
                refs = "".join(
                    f"<li>{html.escape(r)}</li>" for r in f["references"]
                )
                refs_html = (
                    f'<div class="sec"><div class="sec-h">References</div>'
                    f'<ul class="refs">{refs}</ul></div>'
                )
            remediation = ""
            if f.get("remediation"):
                remediation = (
                    f'<div class="sec"><div class="sec-h">Remediation</div>'
                    f'<pre class="remediation">{html.escape(f["remediation"])}</pre></div>'
                )
            parts.append(
                f'''<div class="card" data-sev="{html.escape(sev)}" data-cat="{html.escape(f["category"])}">
  <div class="head">
    <span class="badge {sev_cls}">{html.escape(sev)}</span>
    <span class="title">{html.escape(f["title"])}</span>
    <span class="cid">{html.escape(f["check_id"])}</span>
  </div>
  <div class="body">
    <div class="sec"><div class="sec-h">Description</div><p>{html.escape(f["description"])}</p></div>
    {affected}
    {remediation}
    {refs_html}
  </div>
</div>'''
            )
        return "\n".join(parts)


_TEMPLATE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RHEL 8 Security Audit — {hostname}</title>
<style>
  :root {{
    --bg:#0a0e17; --panel:#111827; --card:#1a2332; --border:#2a3548;
    --text:#e2e8f0; --muted:#94a3b8; --accent:#10b981;
    --critical:#ef4444; --high:#f97316; --medium:#eab308; --low:#22c55e; --info:#38bdf8;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
         font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;
         line-height:1.55; }}
  .wrap {{ max-width:1180px; margin:0 auto; padding:2.5rem 1.5rem; }}
  h1 {{ font-size:1.4rem; margin:0 0 .15rem 0; }}
  .sub {{ color:var(--muted); font-size:.85rem; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
           gap:1rem; margin:1.5rem 0; }}
  .stat {{ background:var(--panel); border:1px solid var(--border);
           border-radius:8px; padding:1rem; }}
  .stat .lbl {{ color:var(--muted); font-size:.7rem; text-transform:uppercase;
                letter-spacing:.08em; margin-bottom:.3rem; }}
  .stat .val {{ font-size:1.6rem; font-weight:700; }}
  .stat.crit .val {{ color:var(--critical); }}
  .stat.high .val {{ color:var(--high); }}
  .stat.med .val {{ color:var(--medium); }}
  .stat.low .val {{ color:var(--low); }}
  .stat.info .val {{ color:var(--info); }}
  .risk {{ background:var(--panel); border:1px solid var(--border);
           border-radius:8px; padding:1rem 1.25rem; margin-bottom:1.5rem;
           display:flex; justify-content:space-between; align-items:center; }}
  .risk .num {{ font-size:2rem; font-weight:700; color:{risk_color}; }}
  .risk .lbl-r {{ color:var(--muted); font-size:.85rem; }}
  .filter {{ display:flex; gap:.5rem; margin-bottom:1rem; flex-wrap:wrap; }}
  .filter button {{ background:var(--card); color:var(--text);
                    border:1px solid var(--border); padding:.4rem .8rem;
                    border-radius:6px; font-size:.8rem; cursor:pointer; }}
  .filter button.active {{ background:var(--accent); border-color:var(--accent);
                           color:#0a0e17; font-weight:600; }}
  .card {{ background:var(--card); border:1px solid var(--border);
           border-radius:8px; margin-bottom:.6rem; }}
  .card .head {{ padding:.85rem 1rem; cursor:pointer; display:flex;
                 align-items:center; gap:.8rem; }}
  .card .body {{ display:none; padding:0 1rem 1rem; border-top:1px solid var(--border); }}
  .card.open .body {{ display:block; }}
  .badge {{ font-size:.65rem; font-weight:700; padding:.25rem .55rem;
            border-radius:4px; text-transform:uppercase; letter-spacing:.05em;
            color:#0a0e17; }}
  .badge.critical {{ background:var(--critical); }}
  .badge.high {{ background:var(--high); }}
  .badge.medium {{ background:var(--medium); }}
  .badge.low {{ background:var(--low); }}
  .badge.info {{ background:var(--info); }}
  .title {{ flex:1; font-weight:500; }}
  .cid {{ color:var(--muted); font-family:monospace; font-size:.75rem; }}
  .sec {{ margin-top:.85rem; }}
  .sec-h {{ color:var(--muted); font-size:.7rem; text-transform:uppercase;
            letter-spacing:.08em; margin-bottom:.3rem; font-weight:600; }}
  .sec p {{ margin:0; color:var(--text); font-size:.85rem; }}
  .affected, .refs {{ list-style:none; padding:.6rem .8rem; margin:0;
                      background:var(--bg); border-radius:6px;
                      font-family:monospace; font-size:.75rem;
                      max-height:200px; overflow:auto; }}
  .affected li, .refs li {{ padding:.15rem 0; }}
  .refs li {{ color:var(--accent); }}
  .remediation {{ background:rgba(34,197,94,.06); border-left:3px solid var(--low);
                  padding:.7rem .9rem; border-radius:0 6px 6px 0;
                  font-family:monospace; font-size:.78rem; color:var(--text);
                  white-space:pre-wrap; margin:0; }}
  .empty {{ text-align:center; padding:3rem; color:var(--muted); }}
  .footer {{ margin-top:2rem; padding-top:1.5rem; border-top:1px solid var(--border);
             text-align:center; color:var(--muted); font-size:.75rem; }}
</style>
</head><body>
<div class="wrap">
  <h1>RHEL 8 Security Audit Report</h1>
  <div class="sub">Host <b>{hostname}</b> · RHEL {rhel} · Kernel {kernel}
                · Bundle collected {collected}
                · Report generated {generated}
                · Scanner v{version}</div>

  <div class="risk">
    <div>
      <div class="lbl-r">Risk Score</div>
      <div class="num">{risk_score}</div>
    </div>
    <div style="text-align:right">
      <div class="lbl-r">Overall Risk</div>
      <div style="font-size:1.2rem;font-weight:600;color:{risk_color}">{risk_label}</div>
    </div>
  </div>

  <div class="grid">
    <div class="stat crit"><div class="lbl">Critical</div><div class="val">{crit}</div></div>
    <div class="stat high"><div class="lbl">High</div><div class="val">{high}</div></div>
    <div class="stat med"><div class="lbl">Medium</div><div class="val">{med}</div></div>
    <div class="stat low"><div class="lbl">Low</div><div class="val">{low}</div></div>
    <div class="stat info"><div class="lbl">Info</div><div class="val">{info}</div></div>
    <div class="stat"><div class="lbl">Total</div><div class="val">{total}</div></div>
  </div>

  <div class="filter">
    <button class="active" data-f="all">All ({total})</button>
    <button data-f="CRITICAL">Critical ({crit})</button>
    <button data-f="HIGH">High ({high})</button>
    <button data-f="MEDIUM">Medium ({med})</button>
    <button data-f="LOW">Low ({low})</button>
    <button data-f="INFO">Info ({info})</button>
  </div>

  <div id="findings">
    {findings_html}
  </div>

  <div class="footer">
    Modules: {modules} · Source: {bundle_source} · Generated by RHEL 8 Security Audit v{version}
  </div>
</div>
<script>
  document.querySelectorAll('.card .head').forEach(h => {{
    h.addEventListener('click', () => h.parentElement.classList.toggle('open'));
  }});
  document.querySelectorAll('.filter button').forEach(b => {{
    b.addEventListener('click', () => {{
      document.querySelectorAll('.filter button').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      const f = b.dataset.f;
      document.querySelectorAll('#findings .card').forEach(c => {{
        c.style.display = (f === 'all' || c.dataset.sev === f) ? '' : 'none';
      }});
    }});
  }});
</script>
</body></html>"""

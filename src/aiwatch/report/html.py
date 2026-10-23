"""Self-contained static HTML dashboard (no external assets; data embedded as JSON)."""

from __future__ import annotations

import html
import json
from typing import Any

from ..monitor.state import Delta
from ..rules import ATLAS_NAMES, LLM02, LLM03, LLM04, LLM05, LLM06
from ..scanner import ScanResult

OWASP_ALL = [
    "LLM01:2025 Prompt Injection", LLM02, LLM03, LLM04, LLM05, LLM06,
    "LLM07:2025 System Prompt Leakage", "LLM08:2025 Vector and Embedding Weaknesses",
    "LLM09:2025 Misinformation", "LLM10:2025 Unbounded Consumption",
]

CSS = r"""
:root{--bg:#07080d;--panel:#0e1019;--line:#1d2133;--txt:#e7e9f3;--dim:#8a90a8;--amber:#ffb020;
--cyan:#22d3ee;--mag:#f472b6;--lime:#a3e635;--crit:#d946ef;--high:#f43f5e;--med:#f59e0b;
--low:#38bdf8;--info:#64748b}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 10% -10%,#2a1a0033,
transparent),var(--bg);color:var(--txt);font:14px/1.5 ui-sans-serif,system-ui,-apple-system,
"Segoe UI",Roboto,sans-serif}
a{color:var(--amber)}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
header{padding:28px 32px 8px;display:flex;flex-wrap:wrap;gap:12px 24px;align-items:flex-end}
h1{margin:0;font-size:26px;letter-spacing:.5px}h1 span{color:var(--amber);text-shadow:0 0 18px #ffb02088}
.sub{color:var(--dim)}main{padding:8px 32px 48px;display:grid;gap:18px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.kpi b{display:block;font-size:28px;line-height:1.1}.kpi small{color:var(--dim)}
.kpi.new b{color:var(--amber);text-shadow:0 0 14px #ffb02066}.kpi.res b{color:var(--lime)}
.kpi.crit b{color:var(--high)}
.grid2{display:grid;grid-template-columns:1.2fr 1fr;gap:18px}@media(max-width:900px){.grid2{grid-template-columns:1fr}
header,main{padding-left:16px;padding-right:16px}}
section{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px 18px;min-width:0}
h2{margin:0 0 10px;font-size:15px;letter-spacing:.3px;color:#cfd3e6}
.bar{display:flex;height:12px;border-radius:6px;overflow:hidden;background:#151827;margin:6px 0 10px}
.bar i{display:block}.legend{display:flex;flex-wrap:wrap;gap:10px;color:var(--dim);font-size:12px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}.sev-medium{background:var(--med)}
.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;color:#0b0c12}
.st{display:inline-block;padding:1px 7px;border-radius:6px;font-size:11px;border:1px solid var(--line);color:var(--dim)}
.st.new{color:var(--amber);border-color:#ffb02066;box-shadow:0 0 10px #ffb02033 inset}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--dim);font-weight:500;font-size:12px;position:sticky;top:0;background:var(--panel)}
.tbl{max-height:640px;overflow:auto}.filters{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
.filters button,.filters input{background:#121524;color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:5px 10px;font:inherit;font-size:12px}
.filters button.on{border-color:var(--amber);color:var(--amber)}
.filters input{min-width:200px;flex:1}
.map td:first-child{white-space:nowrap}.map .n{font-weight:700;color:var(--amber)}.map .z{color:#3b4058}
.fix{color:var(--lime)}.muted{color:var(--dim)}svg text{fill:var(--dim);font-size:10px}
footer{color:var(--dim);padding:0 32px 32px;font-size:12px}
"""

JS = r"""
const D=JSON.parse(document.getElementById('aw-data').textContent);
const SEV=['critical','high','medium','low','info'];
D.findings.sort((a,b)=>(a.status==='new'?0:1)-(b.status==='new'?0:1));
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let fSev=null,fStatus=null,fCat=null,q='';
function row(f){const adv=f.details&&f.details.advisory;
 const id=adv?`<a href="https://osv.dev/vulnerability/${esc(adv)}" target="_blank" rel="noopener">${esc(adv)}</a>`:esc(f.rule_id);
 const st=f.status?`<span class="st ${f.status}">${esc(f.status)}${f.change&&f.change!=='baseline'?' · '+esc(f.change):''}</span>`:'';
 const fix=f.fix?`<span class="fix">${esc(f.fix.description)}</span> <span class="muted">(${esc(f.fix.safety)})</span>`:'<span class="muted">manual</span>';
 const tags=[...(f.owasp||[]).map(o=>o.split(' ')[0]),...(f.atlas||[])].join(' · ');
 return `<tr><td><span class="pill sev-${f.severity}">${f.severity}</span></td><td>${st}</td><td class="mono">${id}<br><span class="muted">${adv?esc(f.rule_id)+' · ':''}${esc(f.category)}</span></td>
 <td>${esc(f.message)}<br><span class="muted mono">${esc(tags)}</span></td><td class="mono">${esc(f.file)}${f.line?':'+f.line:''}</td><td>${fix}</td></tr>`}
function draw(){const rows=D.findings.filter(f=>(!fSev||f.severity===fSev)&&(!fStatus||f.status===fStatus)&&(!fCat||f.category===fCat)
 &&(!q||JSON.stringify(f).toLowerCase().includes(q)));
 document.getElementById('rows').innerHTML=rows.map(row).join('')||'<tr><td colspan=6 class="muted">No findings match.</td></tr>';
 document.getElementById('shown').textContent=rows.length+' of '+D.findings.length}
function btns(id,vals,set){const el=document.getElementById(id);
 el.innerHTML=['all',...vals].map(v=>`<button data-v="${v}" class="${v==='all'?'on':''}">${v}</button>`).join('');
 el.onclick=e=>{const b=e.target.closest('button');if(!b)return;[...el.children].forEach(c=>c.classList.remove('on'));b.classList.add('on');set(b.dataset.v==='all'?null:b.dataset.v);draw()}}
btns('fsev',SEV.filter(s=>D.findings.some(f=>f.severity===s)),v=>fSev=v);
btns('fst',[...new Set(D.findings.map(f=>f.status).filter(Boolean))],v=>fStatus=v);
btns('fcat',[...new Set(D.findings.map(f=>f.category))].sort(),v=>fCat=v);
document.getElementById('q').oninput=e=>{q=e.target.value.toLowerCase();draw()};draw();
"""


def _trend_svg(runs: list[dict[str, Any]]) -> str:
    if len(runs) < 2:
        return '<p class="muted">Trend appears after the second monitor run.</p>'
    w, h, pad = 520, 150, 26
    tot = [r["summary"].get("findings", 0) for r in runs]
    new = [r.get("new") or 0 for r in runs]
    mx = max(tot + new + [1])
    n = len(runs)

    def x(i: int) -> float:
        return pad + i * (w - 2 * pad) / (n - 1)

    def y(v: float) -> float:
        return h - pad - v * (h - 2 * pad) / mx

    line = " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(tot))
    bw = max(4.0, (w - 2 * pad) / n * 0.35)
    bars = "".join(f'<rect x="{x(i) - bw / 2:.1f}" y="{y(v):.1f}" width="{bw:.1f}" '
                   f'height="{h - pad - y(v):.1f}" fill="#ffb020" opacity=".8"/>'
                   for i, v in enumerate(new) if v)
    labels = "".join(f'<text x="{x(i):.1f}" y="{h - 8}" text-anchor="middle">#{r["id"]}</text>'
                     for i, r in enumerate(runs) if n <= 14 or i % max(1, n // 10) == 0)
    pts = "".join(f'<circle cx="{x(i):.1f}" cy="{y(v):.1f}" r="3" fill="#22d3ee"><title>run '
                  f'#{runs[i]["id"]}: {v} open, {new[i]} new</title></circle>'
                  for i, v in enumerate(tot))
    return (f'<svg viewBox="0 0 {w} {h}" width="100%" role="img" aria-label="open findings per '
            f'run">{bars}<polyline points="{line}" fill="none" stroke="#22d3ee" stroke-width="2"/>'
            f'{pts}<text x="{pad}" y="14">{mx}</text>{labels}</svg>'
            '<div class="legend"><span><i class="dot" style="background:#22d3ee"></i>open findings'
            '</span><span><i class="dot" style="background:#ffb020"></i>new in run</span></div>')


def render(res: ScanResult, delta: Delta | None = None, runs: list[dict[str, Any]] | None = None,
           title: str | None = None) -> str:
    s = res.summary()
    m = res.meta
    data = res.to_dict()
    data.pop("components", None)
    c = delta.counts() if delta else {"new": 0, "known": 0, "resolved": 0}
    sev = s["by_severity"]
    total = max(1, sum(sev.values()))
    bar = "".join(f'<i class="sev-{k}" style="width:{v * 100 / total:.2f}%" title="{k}: {v}"></i>'
                  for k, v in sev.items() if v)
    legend = "".join(f'<span><i class="dot sev-{k}"></i>{k} {v}</span>' for k, v in sev.items())
    owasp: dict[str, int] = {}
    atlas: dict[str, int] = {}
    for f in res.findings:
        for o in f.owasp:
            owasp[o] = owasp.get(o, 0) + 1
        for a in f.atlas:
            atlas[a] = atlas.get(a, 0) + 1
    omap = "".join(
        f'<tr><td class="mono">{html.escape(o.split(" ", 1)[0])}</td><td>'
        f'{html.escape(o.split(" ", 1)[1])}</td><td class="{"n" if owasp.get(o) else "z"}">'
        f'{owasp.get(o, 0) or "–"}</td></tr>' for o in OWASP_ALL)
    amap = "".join(f'<tr><td class="mono">{a}</td><td>{html.escape(ATLAS_NAMES.get(a, ""))}</td>'
                   f'<td class="n">{n}</td></tr>' for a, n in sorted(atlas.items()))
    cats = "".join(f'<tr><td>{html.escape(k)}</td><td class="n">{v}</td></tr>'
                   for k, v in s["by_category"].items())
    comps = res.components
    inv = (f'{len(comps)} components ({s["pinned_components"]} pinned) · {m["files"]} files · '
           f'{m["python_files"]} Python/notebooks · {m["mcp_configs"]} MCP configs · '
           f'{(m.get("artifacts") or {}).get("files", 0)} model artifacts · '
           f'{len(m["hf_refs"])} HF model refs')
    runs = runs or []
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    t = html.escape(title or res.root)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>aiwatch · {t}</title><style>{CSS}</style></head><body>
<header><div><h1><span>aiwatch</span> · AI-stack vulnerability monitor</h1>
<div class="sub">{t} · scanned {html.escape(m['scanned_at'])} · {html.escape(m['advisory_source'])}
{(' · advisories as of ' + html.escape(m['as_of'])) if m.get('as_of') else ''} · scan {m['seconds']:.2f}s</div></div></header>
<main>
<div class="kpis">
<div class="kpi"><b>{s['findings']}</b><small>open findings</small></div>
<div class="kpi crit"><b>{sev['critical'] + sev['high']}</b><small>critical + high</small></div>
<div class="kpi new"><b>{c['new'] if delta and not delta.first_run else '–'}</b><small>new since last run</small></div>
<div class="kpi res"><b>{c['resolved'] if delta and not delta.first_run else '–'}</b><small>resolved since last run</small></div>
<div class="kpi"><b>{s['advisories']}</b><small>advisories · {s['vulnerable_packages']} packages</small></div>
<div class="kpi"><b>{s['fixable']}</b><small>auto-fixable findings</small></div>
</div>
<div class="grid2">
<section><h2>Severity</h2><div class="bar">{bar}</div><div class="legend">{legend}</div>
<h2 style="margin-top:16px">Trend ({len(runs)} run{'s' if len(runs) != 1 else ''})</h2>{_trend_svg(runs)}</section>
<section><h2>Attack surface</h2><p class="muted">{inv}</p>
<table><tbody>{cats}</tbody></table></section>
</div>
<div class="grid2">
<section class="map"><h2>OWASP Top 10 for LLM Applications 2025</h2><table><tbody>{omap}</tbody></table></section>
<section class="map"><h2>MITRE ATLAS techniques</h2><table><tbody>{amap or '<tr><td class="muted">none</td></tr>'}</tbody></table></section>
</div>
<section><h2>Findings <span class="muted" id="shown"></span></h2>
<div class="filters"><span id="fsev"></span><span id="fst"></span><span id="fcat"></span>
<input id="q" placeholder="search package, advisory, file…" aria-label="search findings"></div>
<div class="tbl"><table><thead><tr><th>sev</th><th>status</th><th>id</th><th>finding</th><th>location</th><th>fix</th></tr></thead>
<tbody id="rows"></tbody></table></div></section>
</main>
<footer>Generated by <a href="https://github.com/sushmit-gujar/aiwatch">aiwatch</a> {html.escape(data['tool']['version'])}. Advisory data: OSV.dev (GHSA, PYSEC). Defensive tool; findings are static and may need human review.</footer>
<script type="application/json" id="aw-data">{blob}</script><script>{JS}</script></body></html>
"""

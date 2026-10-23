"""Markdown for the monitor issue (and PR bodies)."""

from __future__ import annotations

from ..models import Finding
from ..monitor.state import Delta
from ..scanner import ScanResult

ICON = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🔵", "info": "⚪"}


def _row(f: Finding) -> str:
    adv = f.details.get("advisory")
    link = f"[{adv}](https://osv.dev/vulnerability/{adv})" if adv else f.rule_id
    fix = f.fix.description if f.fix else "manual"
    loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
    msg = f.message.replace("|", "\\|")[:140]
    return f"| {ICON[f.severity.label]} {f.severity.label} | {f.change or f.status} | {link} | " \
           f"{msg} | {loc} | {fix} |"


def render(res: ScanResult, delta: Delta | None, dashboard_url: str | None = None,
           limit: int = 60) -> str:
    s = res.summary()
    m = res.meta
    lines = ["<!-- aiwatch-monitor -->", "# aiwatch: AI-stack vulnerability monitor", ""]
    if delta is not None:
        c = delta.counts()
        lines.append(f"**Run #{delta.run_id}** · {m['scanned_at']} · {m['advisory_source']} · "
                     f"scan {m['seconds']:.2f}s")
        lines.append("")
        lines.append("| new | known | resolved | total open | auto-fixable |")
        lines.append("|---:|---:|---:|---:|---:|")
        lines.append(f"| **{c['new']}** | {c['known']} | {c['resolved']} | {s['findings']} | "
                     f"{s['fixable']} |")
        kinds = [f"{k[4:].replace('_', '-')}: {v}" for k, v in c.items() if k.startswith("new_")]
        if kinds:
            lines += ["", "New by cause: " + " · ".join(kinds)]
    sev = " · ".join(f"{k}: {v}" for k, v in s["by_severity"].items() if v)
    lines += ["", f"Open findings by severity: {sev or 'none'}"]
    if dashboard_url:
        lines += ["", f"Dashboard: {dashboard_url}"]
    show = delta.new if delta is not None else res.findings
    if show:
        lines += ["", f"## New findings ({len(show)})" if delta else "## Findings", "",
                  "| severity | change | id | finding | location | fix |",
                  "|---|---|---|---|---|---|"]
        lines += [_row(f) for f in show[:limit]]
        if len(show) > limit:
            lines.append(f"\n… and {len(show) - limit} more (see SARIF / dashboard).")
    if delta is not None and delta.resolved:
        lines += ["", f"## Resolved since last run ({len(delta.resolved)})", ""]
        lines += [f"- {r.get('rule_id')} `{r.get('file')}` {r.get('message', '')[:100]}"
                  for r in delta.resolved[:30]]
    lines += ["", "_Run `aiwatch fix <path> --dry-run` to preview remediations._"]
    return "\n".join(lines) + "\n"

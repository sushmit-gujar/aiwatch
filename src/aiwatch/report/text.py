from __future__ import annotations

from ..models import Finding
from ..monitor.state import Delta
from ..scanner import ScanResult

COLORS = {"critical": "\033[1;35m", "high": "\033[1;31m", "medium": "\033[33m",
          "low": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"


def _line(f: Finding, color: bool) -> str:
    sev = f.severity.label
    tag = f"{COLORS[sev]}{sev.upper():8}{RESET}" if color else f"{sev.upper():8}"
    loc = f"{f.file}:{f.line}" if f.line else f.file
    st = f" [{f.status}{'/' + f.change if f.change else ''}]" if f.status else ""
    fix = f"  → fix: {f.fix.description}" if f.fix else ""
    return f"  {tag} {f.rule_id} {loc}{st}\n           {f.message}{fix}"


def render(res: ScanResult, delta: Delta | None = None, color: bool = False,
           limit: int = 60) -> str:
    s = res.summary()
    m = res.meta
    out = [f"aiwatch · {res.root} · {m['files']} files · {s['components']} components "
           f"({s['pinned_components']} pinned) · {m['seconds']:.2f}s · {m['advisory_source']}"]
    sev = ", ".join(f"{k} {v}" for k, v in s["by_severity"].items() if v)
    out.append(f"{s['findings']} findings ({sev or 'none'}) · {s['advisories']} advisories in "
               f"{s['vulnerable_packages']} packages · {s['fixable']} auto-fixable")
    if delta is not None:
        c = delta.counts()
        extra = ", ".join(f"{k[4:].replace('_', '-')} {v}" for k, v in c.items()
                          if k.startswith("new_"))
        out.append(f"monitor run #{delta.run_id}: NEW {c['new']}"
                   + (f" ({extra})" if extra else "")
                   + f" · known {c['known']} · resolved {c['resolved']}")
    shown = delta.new if delta is not None and not delta.first_run else res.findings
    if delta is not None and not delta.first_run:
        out.append("New findings:" if shown else "No new findings.")
    for f in shown[:limit]:
        out.append(_line(f, color))
    if len(shown) > limit:
        out.append(f"  … {len(shown) - limit} more (use --format json / html)")
    return "\n".join(out) + "\n"

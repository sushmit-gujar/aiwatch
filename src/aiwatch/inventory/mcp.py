"""MCP client configuration checks (Claude Desktop, Cursor, VS Code, Windsurf, generic mcp.json)."""

from __future__ import annotations

import json
import re
from typing import Any

from packaging.utils import canonicalize_name

from ..models import Component, Edit, Finding, Fix
from ..rules import make
from .walk import line_of

MCP_FILE = re.compile(r"(^|/)(\.?mcp\.json|claude_desktop_config\.json|mcp_config\.json|"
                      r"\.cursor/mcp\.json|\.vscode/mcp\.json|\.roo/mcp\.json)$")
NPM_RUNNERS = {"npx", "bunx", "pnpx"}
BROAD_ROOTS = {"/", "~", "~/", "$HOME", "${HOME}", "%USERPROFILE%", "C:\\", "C:/", "/home",
               "/Users", "/root", "${env:HOME}", "${userHome}"}
NPM_SPEC = re.compile(r"^(@[^/@\s]+/[^@\s]+|[^@\s][^@\s]*)(?:@(.+))?$")
IMAGE = re.compile(r"^[\w.-]+(\.[\w.-]+)*(:\d+)?/[\w./-]+(:[\w.-]+)?(@sha256:[0-9a-f]{64})?$")
EXACT = re.compile(r"^\d+\.\d+\.\d+([-+][\w.-]+)?$")


def is_mcp_config(relpath: str, text: str | None = None) -> bool:
    if MCP_FILE.search(relpath):
        return True
    return bool(relpath.endswith(".json") and text and '"mcpServers"' in text)


def _strip_jsonc(text: str) -> str:
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _servers(data: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(data, dict):
        return {}
    for key in ("mcpServers", "servers"):
        s = data.get(key)
        if isinstance(s, dict):
            return {k: v for k, v in s.items() if isinstance(v, dict)}
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        return _servers(mcp)
    return {}


def _package_arg(args: list[str]) -> tuple[int, str] | None:
    skip_next = {"-p", "--package", "--from", "--with", "--python", "--registry"}
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--from",) and i + 1 < len(args):
            return i + 1, args[i + 1]
        if a in skip_next:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return i, a
    return None


def scan_mcp(text: str, relpath: str, db: Any) -> tuple[list[Finding], list[Component]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = json.loads(_strip_jsonc(text))
        except json.JSONDecodeError:
            return [], []
    findings: list[Finding] = []
    comps: list[Component] = []
    for sname, srv in _servers(data).items():
        anchor = max(text.find(f'"{sname}"'), 0)
        line = line_of(text, anchor)
        cmd = str(srv.get("command", "")).rsplit("/", 1)[-1].lower()
        args = [str(a) for a in srv.get("args", []) if isinstance(a, (str, int, float))]
        pkg_name = ""

        def arg_span(value: str, _anchor: int = anchor) -> tuple[int, int] | None:
            pos = text.find(json.dumps(value), _anchor)
            return (pos + 1, pos + 1 + len(value)) if pos >= 0 else None

        if cmd in NPM_RUNNERS or cmd in ("uvx", "pipx") or (cmd == "uv" and "tool" in args):
            eco = "npm" if cmd in NPM_RUNNERS else "PyPI"
            pa = _package_arg(args[2:] if cmd == "uv" else args)
            if pa:
                _, spec = pa
                if eco == "npm":
                    m = NPM_SPEC.match(spec)
                    name, ver = (m.group(1), m.group(2)) if m else (spec, None)
                else:
                    m = re.match(r"^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?(?:(==|@)(.+))?$", spec)
                    name, ver = (m.group(1), m.group(3)) if m else (spec, None)
                    name = canonicalize_name(name)
                pkg_name = name
                exact = ver is not None and (EXACT.match(ver) if eco == "npm" else
                                             re.match(r"^\d[\w.!+-]*$", ver))
                span = arg_span(spec)
                if exact:
                    vspan = (span[1] - len(ver), span[1]) if span and ver else None
                    comps.append(Component(eco, name, ver, spec, relpath, line, "mcp", True,
                                           vspan))
                else:
                    f = make("AW300", f"server {sname!r} runs {spec!r} via {cmd} without an "
                             "exact version", relpath, line, key=f"{sname}|{name}",
                             server=sname, package=name, ecosystem=eco)
                    latest = None
                    if db is not None:
                        if eco == "npm":
                            latest = db.npm_latest(name)
                        else:
                            from ..advisories import versions as V
                            rel = [r for r in db.releases("PyPI", name)
                                   if not V.is_prerelease("PyPI", r)]
                            latest = V.sort_versions("PyPI", rel)[-1] if rel else None
                    if latest and span:
                        new = f"{name}@{latest}" if eco == "npm" else f"{name}=={latest}"
                        f.fix = Fix(f"pin {name} to {latest} (current latest)",
                                    [Edit(relpath, span[0], span[1], new)], "safe", latest)
                    findings.append(f)
        elif cmd in ("docker", "podman"):
            for a in args:
                if a.startswith("-") or "=" in a or a in ("run", "--rm", "-i"):
                    continue
                if IMAGE.match(a) or re.match(r"^[\w.-]+:[\w.-]+$", a):
                    if "@sha256:" not in a:
                        findings.append(make("AW303", f"server {sname!r} image {a!r} not pinned "
                                             "by digest", relpath, line, key=f"{sname}|{a}"))
                    break

        if "filesystem" in (pkg_name or " ".join(args)).lower():
            for a in args:
                if a.rstrip("/\\") in {r.rstrip("/\\") for r in BROAD_ROOTS} or a in BROAD_ROOTS:
                    findings.append(make("AW301", f"server {sname!r} exposes {a!r}", relpath, line,
                                         key=f"{sname}|{a}"))
        url = srv.get("url") or srv.get("serverUrl") or ""
        if isinstance(url, str) and url.startswith("http://") and not re.match(
                r"^http://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:|/|$)", url):
            findings.append(make("AW302", f"server {sname!r} uses {url}", relpath, line,
                                 key=f"{sname}|{url}"))
        for k in ("alwaysAllow", "autoApprove"):
            v = srv.get(k)
            if v:
                findings.append(make("AW304", f"server {sname!r} {k}: {v}", relpath, line,
                                     key=f"{sname}|{k}"))
    return findings, comps

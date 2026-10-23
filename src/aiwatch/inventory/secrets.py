"""Hard-coded AI-provider and cloud credentials (values are never stored, only hashed)."""

from __future__ import annotations

import hashlib
import re

from ..models import Finding
from ..rules import make

PATTERNS = [
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    ("Replicate token", re.compile(r"\br8_[A-Za-z0-9]{30,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}")),
]
TEXT_EXT = (".py", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".sh", ".ipynb", ".env",
            ".js", ".ts", ".conf", ".txt", ".md")
PLACEHOLDER = re.compile(r"(x{6,}|your[_-]?|example|placeholder|<|\$\{|\.\.\.)", re.I)


def wants(relpath: str) -> bool:
    name = relpath.rsplit("/", 1)[-1]
    if name.endswith((".lock", "-lock.json")) or name == "package-lock.json":
        return False
    return name.startswith(".env") or name.endswith(TEXT_EXT)


def mask(s: str) -> str:
    return s[:6] + "…" + s[-2:] if len(s) > 10 else "…"


def scan_secrets(text: str, relpath: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for i, ln in enumerate(text.splitlines(), start=1):
        for label, rx in PATTERNS:
            for m in rx.finditer(ln):
                val = m.group(0)
                if PLACEHOLDER.search(val) or val in seen:
                    continue
                seen.add(val)
                digest = hashlib.sha256(val.encode()).hexdigest()[:16]
                out.append(make("AW400", f"{label} {mask(val)}", relpath, i,
                                key=f"secret|{digest}", kind=label, sha256_16=digest))
                break
    return out

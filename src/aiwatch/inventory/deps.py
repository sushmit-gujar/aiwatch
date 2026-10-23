"""Python dependency inventory: requirements files, pyproject.toml, uv/poetry/Pipfile locks."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from ..models import Component
from .walk import line_of, read_text, rel

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

# Packages whose compromise or vulnerability is AI-stack specific (used for AW101).
_AI_NAMES = """
    torch torchvision torchaudio tensorflow keras jax flax transformers diffusers accelerate
    peft trl datasets tokenizers safetensors huggingface-hub sentence-transformers langchain
    langchain-core langchain-community langchain-openai langchain-experimental langgraph
    llama-index llama-index-core llama-cpp-python vllm mlflow gradio streamlit openai anthropic
    litellm ollama chromadb faiss-cpu faiss-gpu onnx onnxruntime xformers bitsandbytes ray
    bentoml haystack-ai dspy crewai pyautogen autogen-agentchat guidance unstructured
    text-generation lmdeploy sglang mcp fastmcp nltk scikit-learn joblib skops pandasai
    pymilvus qdrant-client weaviate-client pinecone-client
"""
AI_PACKAGES = {canonicalize_name(n) for n in _AI_NAMES.split()}

REQ_NAME = re.compile(r"(^|/)([\w.-]*requirements[\w.-]*|constraints[\w.-]*)\.(txt|in)$")


def is_requirements(path: str) -> bool:
    return bool(REQ_NAME.search(path)) or "/requirements/" in f"/{path}"


def _exact(req: Requirement) -> str | None:
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "===") and "*" not in specs[0].version:
        return specs[0].version
    return None


def parse_requirements(text: str, relpath: str) -> list[Component]:
    out: list[Component] = []
    offset = 0
    for i, raw in enumerate(text.splitlines(keepends=True), start=1):
        line_start = offset
        offset += len(raw)
        line = raw.split(" #", 1)[0].split("\t#", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http:", "https:", ".", "/")):
            continue
        line = line.split(" --hash", 1)[0].rstrip("\\ ").strip()
        try:
            req = Requirement(line)
        except InvalidRequirement:
            continue
        ver = _exact(req)
        span = None
        if ver:
            m = re.search(r"={2,3}\s*(" + re.escape(ver) + r")", raw)
            if m:
                span = (line_start + m.start(1), line_start + m.end(1))
        out.append(Component("PyPI", canonicalize_name(req.name), ver, line, relpath, i,
                             "requirements", True, span))
    return out


def _find_string(raw: str, needle: str, start: int) -> int:
    for q in ('"', "'"):
        idx = raw.find(q + needle + q, start)
        if idx >= 0:
            return idx + 1
    return raw.find(needle, start)


def parse_pyproject(raw: str, relpath: str) -> list[Component]:
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError:
        return []
    out: list[Component] = []
    strings: list[str] = []
    proj = data.get("project", {})
    strings += list(proj.get("dependencies", []) or [])
    for v in (proj.get("optional-dependencies", {}) or {}).values():
        strings += list(v)
    for v in (data.get("dependency-groups", {}) or {}).values():
        strings += [s for s in v if isinstance(s, str)]
    cursor = 0
    for s in strings:
        try:
            req = Requirement(s)
        except InvalidRequirement:
            continue
        pos = _find_string(raw, s, cursor)
        if pos >= 0:
            cursor = pos + len(s)
        ver = _exact(req)
        span = None
        if ver and pos >= 0:
            m = re.search(r"={2,3}\s*(" + re.escape(ver) + r")", s)
            if m:
                span = (pos + m.start(1), pos + m.end(1))
        out.append(Component("PyPI", canonicalize_name(req.name), ver, s, relpath,
                             line_of(raw, max(pos, 0)), "pyproject", True, span))
    # Poetry style
    poetry = data.get("tool", {}).get("poetry", {})
    groups = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    for g in (poetry.get("group", {}) or {}).values():
        groups.append(g.get("dependencies", {}))
    for deps in groups:
        for name, spec in (deps or {}).items():
            if name.lower() == "python":
                continue
            vs = spec.get("version") if isinstance(spec, dict) else spec
            if not isinstance(vs, str):
                continue
            m = re.fullmatch(r"\s*(?:==)?\s*(\d[\w.!+-]*)\s*", vs)
            ver = m.group(1) if m else None
            pos = raw.find(name)
            span = None
            if ver:
                vpos = raw.find(f'"{vs}"', pos)
                if vpos >= 0:
                    inner = vs.index(ver)
                    span = (vpos + 1 + inner, vpos + 1 + inner + len(ver))
            out.append(Component("PyPI", canonicalize_name(name), ver, f"{name} {vs}", relpath,
                                 line_of(raw, max(pos, 0)), "pyproject", True, span))
    return out


def parse_toml_lock(raw: str, relpath: str, kind: str) -> list[Component]:
    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError:
        return []
    out = []
    for pkg in data.get("package", []):
        name, ver = pkg.get("name"), pkg.get("version")
        if not name or not ver:
            continue
        src = pkg.get("source", {})
        if isinstance(src, dict) and ("editable" in src or "virtual" in src):
            continue
        pos = raw.find(f'name = "{name}"')
        out.append(Component("PyPI", canonicalize_name(name), str(ver), f"{name}=={ver}",
                             relpath, line_of(raw, max(pos, 0)), kind, False))
    return out


def parse_pipfile_lock(raw: str, relpath: str) -> list[Component]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    out = []
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            v = (meta or {}).get("version", "")
            if v.startswith("=="):
                pos = raw.find(f'"{name}"')
                out.append(Component("PyPI", canonicalize_name(name), v[2:], f"{name}{v}",
                                     relpath, line_of(raw, max(pos, 0)), "Pipfile.lock", False))
    return out


def collect(root: Path, files: list[Path]) -> list[Component]:
    comps: list[Component] = []
    for p in files:
        r = rel(root, p)
        name = p.name
        if name == "pyproject.toml":
            kind = "pyproject"
        elif name in ("uv.lock", "poetry.lock", "pdm.lock"):
            kind = name
        elif name == "Pipfile.lock":
            kind = "Pipfile.lock"
        elif is_requirements(r):
            kind = "requirements"
        else:
            continue
        text = read_text(p)
        if text is None:
            continue
        if kind == "requirements":
            comps += parse_requirements(text, r)
        elif kind == "pyproject":
            comps += parse_pyproject(text, r)
        elif kind == "Pipfile.lock":
            comps += parse_pipfile_lock(text, r)
        else:
            comps += parse_toml_lock(text, r, kind)
    return comps

"""Python source checks for AI-stack risky patterns, with precise auto-fix edits."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

from ..models import Edit, Finding, Fix, Severity
from ..rules import make
from .textpos import TextIndex

HF_LOADERS = {"from_pretrained"}
HF_FUNCS = {
    "transformers.pipeline": "model",
    "huggingface_hub.hf_hub_download": "repo_id",
    "huggingface_hub.snapshot_download": "repo_id",
    "sentence_transformers.SentenceTransformer": "model_name_or_path",
    "diffusers.DiffusionPipeline.from_pretrained": "pretrained_model_name_or_path",
}
UNSAFE_LOADS = {
    "pickle.load", "pickle.loads", "_pickle.load", "cPickle.load", "joblib.load", "dill.load",
    "dill.loads", "cloudpickle.load", "cloudpickle.loads", "pandas.read_pickle",
    "sklearn.externals.joblib.load",
}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
HF_ID = re.compile(r"^[A-Za-z0-9][\w.-]*(/[\w.-]+)?$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def looks_like_hf_id(s: str, root: Path | None) -> bool:
    if not s or s.startswith((".", "/", "~")) or "\\" in s or not HF_ID.match(s):
        return False
    if s.endswith((".pt", ".bin", ".pkl", ".json", ".safetensors", ".gguf", ".onnx")):
        return False
    return not (root is not None and (root / s).exists())


class _Visitor(ast.NodeVisitor):
    def __init__(self, ctx: CodeContext, relpath: str, text: str) -> None:
        self.ctx = ctx
        self.rel = relpath
        self.text = text
        self.idx = TextIndex(text)
        self.aliases: dict[str, str] = {}
        self.findings: list[Finding] = []

    # imports -------------------------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else \
                a.name.split(".")[0]

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def _dotted(self, n: ast.AST) -> str | None:
        parts = []
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            parts.append(self.aliases.get(n.id, n.id))
            return ".".join(reversed(parts))
        if isinstance(n, ast.Call):  # e.g. Foo().from_pretrained
            inner = self._dotted(n.func)
            if inner:
                parts.append(inner)
                return ".".join(reversed(parts))
        return None

    # helpers -------------------------------------------------------------------------------
    def _off(self, node: ast.AST, end: bool = False) -> int:
        if end:
            return self.idx.offset(node.end_lineno or node.lineno,  # type: ignore[attr-defined]
                                   node.end_col_offset or 0)  # type: ignore[attr-defined]
        return self.idx.offset(node.lineno, node.col_offset)  # type: ignore[attr-defined]

    def _snippet(self, node: ast.AST) -> str:
        return ast.unparse(node)[:160]

    def _insert_kw(self, call: ast.Call, text: str) -> Edit:
        """Insert ``, text`` after the last argument (or ``text`` into empty parens)."""
        last: ast.AST | None = None
        for a in list(call.args) + [k.value for k in call.keywords]:
            if last is None or (a.end_lineno, a.end_col_offset) > (  # type: ignore[attr-defined]
                    last.end_lineno, last.end_col_offset):  # type: ignore[attr-defined]
                last = a
        if last is None:
            end = self._off(call, end=True) - 1  # position of ")"
            return Edit(self.rel, end, end, text)
        pos = self._off(last, end=True)
        return Edit(self.rel, pos, pos, f", {text}")

    def _replace(self, node: ast.AST, text: str) -> Edit:
        return Edit(self.rel, self._off(node), self._off(node, end=True), text)

    def _add(self, f: Finding) -> None:
        self.findings.append(f)

    # calls ---------------------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        name = self._dotted(node.func) or ""
        short = name.rsplit(".", 1)[-1]
        kws = {k.arg: k for k in node.keywords if k.arg}
        line = node.lineno
        snippet = self._snippet(node)

        # Hugging Face downloads ------------------------------------------------------------
        model_node: ast.expr | None = None
        if short in HF_LOADERS:
            model_node = node.args[0] if node.args else (
                kws["pretrained_model_name_or_path"].value
                if "pretrained_model_name_or_path" in kws else None)
        else:
            for fq, kw in HF_FUNCS.items():
                if name == fq or (name.endswith("." + fq.rsplit(".", 1)[-1]) and
                                  fq.rsplit(".", 1)[-1] in ("hf_hub_download",
                                                            "snapshot_download")):
                    model_node = kws[kw].value if kw in kws else (
                        node.args[0] if node.args and kw != "model" else None)
                    break
        model_id = None
        if isinstance(model_node, ast.Constant) and isinstance(model_node.value, str) and \
                looks_like_hf_id(model_node.value, self.ctx.root):
            model_id = model_node.value
        if model_id:
            self.ctx.hf_refs.add(model_id)
            rev = kws.get("revision")
            rev_raw = rev.value.value if rev is not None and isinstance(
                rev.value, ast.Constant) else None
            rev_val = rev_raw if isinstance(rev_raw, str) else None
            pinned = isinstance(rev_val, str) and bool(SHA.match(rev_val))
            if rev is None or (isinstance(rev_val, str) and not pinned):
                info = self.ctx.db.hf_model(model_id) if self.ctx.db else None
                fix = None
                if info:
                    sha = info["sha"]
                    edit = (self._insert_kw(node, f'revision="{sha}"') if rev is None
                            else self._replace(rev.value, f'"{sha}"'))
                    fix = Fix(f'pin {model_id} to revision {sha[:12]} (current HEAD of the '
                              "default branch)", [edit], "safe")
                f = make("AW201", f"{short}({model_id!r}) follows a moving revision "
                         f"({rev_val or 'default branch'})", self.rel, line,
                         key=f"{name}|{model_id}", model=model_id)
                f.fix = fix
                self._add(f)
            trc = kws.get("trust_remote_code")
            if trc is not None and isinstance(trc.value, ast.Constant) and trc.value.value is True:
                self._add(make(
                    "AW202",
                    f"trust_remote_code=True for {model_id}" +
                    (" (revision pinned)" if pinned else " with an unpinned revision"),
                    self.rel, line, key=f"trc|{model_id}",
                    severity=Severity.MEDIUM if pinned else Severity.HIGH, model=model_id))
            if self.ctx.db:
                info = self.ctx.db.hf_model(model_id)
                if info and info["weights"] and not any(
                        w.endswith(".safetensors") for w in info["weights"]):
                    exts = sorted({w.rsplit(".", 1)[-1] for w in info["weights"]})
                    self._add(make("AW211", f"{model_id} has no .safetensors weights "
                                   f"({', '.join(exts)} only)", self.rel, line,
                                   key=f"hfw|{model_id}", model=model_id))
        else:
            trc = kws.get("trust_remote_code")
            if trc is not None and isinstance(trc.value, ast.Constant) and trc.value.value is True:
                self._add(make("AW202", f"trust_remote_code=True in {short}()", self.rel, line,
                               key=f"trc|{snippet}"))

        # torch.load -----------------------------------------------------------------------
        if name in ("torch.load",) or (short == "load" and name.startswith("torch.")):
            wo = kws.get("weights_only")
            if wo is None:
                sev = Severity.LOW if self.ctx.torch_safe_default else Severity.MEDIUM
                f = make("AW200", "torch.load() without weights_only=True" +
                         (" (torch>=2.6 defaults to True)" if self.ctx.torch_safe_default
                          else ""), self.rel, line, key=snippet, severity=sev)
                f.fix = Fix("add weights_only=True", [self._insert_kw(node, "weights_only=True")],
                            "review")
                self._add(f)
            elif isinstance(wo.value, ast.Constant) and wo.value.value is False:
                f = make("AW200", "torch.load(weights_only=False) unpickles arbitrary objects",
                         self.rel, line, key=snippet, severity=Severity.HIGH)
                f.fix = Fix("set weights_only=True", [self._replace(wo.value, "True")], "review")
                self._add(f)

        # numpy.load ---------------------------------------------------------------------------
        if name in ("numpy.load", "np.load"):
            ap = kws.get("allow_pickle")
            if ap is not None and isinstance(ap.value, ast.Constant) and ap.value.value is True:
                f = make("AW203", "numpy.load(allow_pickle=True)", self.rel, line, key=snippet)
                f.fix = Fix("set allow_pickle=False", [self._replace(ap.value, "False")],
                            "review")
                self._add(f)

        if name in UNSAFE_LOADS:
            self._add(make("AW204", f"{name}() deserializes executable objects", self.rel, line,
                           key=snippet))

        for kw, rule in (("allow_dangerous_deserialization", "AW205"),
                         ("allow_dangerous_code", "AW206"), ("allow_dangerous_requests", "AW206")):
            k = kws.get(kw)
            if k is not None and isinstance(k.value, ast.Constant) and k.value.value is True:
                self._add(make(rule, f"{short}({kw}=True)", self.rel, line, key=f"{kw}|{snippet}"))

        # yaml.load ------------------------------------------------------------------------------
        if name == "yaml.load":
            loader = kws.get("Loader") or (ast.keyword(arg="Loader", value=node.args[1])
                                           if len(node.args) > 1 else None)
            lname = (self._dotted(loader.value) or "") if loader is not None else ""
            if loader is None or lname.rsplit(".", 1)[-1] not in SAFE_YAML_LOADERS:
                f = make("AW207", f"yaml.load(Loader={lname or 'default'})", self.rel, line,
                         key=snippet)
                if loader is None and isinstance(node.func, ast.Attribute):
                    start = self._off(node.func, end=True) - len("load")
                    f.fix = Fix("use yaml.safe_load", [Edit(self.rel, start, start + 4,
                                                            "safe_load")], "safe")
                elif loader is not None:
                    f.fix = Fix("use yaml.SafeLoader",
                                [self._replace(loader.value, "yaml.SafeLoader")], "review")
                self._add(f)

        # gradio share=True -----------------------------------------------------------------------
        if short == "launch":
            sh = kws.get("share")
            if sh is not None and isinstance(sh.value, ast.Constant) and sh.value.value is True:
                f = make("AW208", "launch(share=True) opens a public tunnel", self.rel, line,
                         key=snippet)
                f.fix = Fix("set share=False", [self._replace(sh.value, "False")], "review")
                self._add(f)

        self.generic_visit(node)


class CodeContext:
    def __init__(self, root: Path | None, db: Any, torch_safe_default: bool = False) -> None:
        self.root = root
        self.db = db
        self.torch_safe_default = torch_safe_default
        self.hf_refs: set[str] = set()


def scan_python(text: str, relpath: str, ctx: CodeContext) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    v = _Visitor(ctx, relpath, text)
    v.visit(tree)
    return v.findings


def scan_notebook(text: str, relpath: str, ctx: CodeContext) -> list[Finding]:
    """Scan code cells; findings are reported but not auto-fixed (edits would be cell-relative)."""
    try:
        nb = json.loads(text)
    except json.JSONDecodeError:
        return []
    out: list[Finding] = []
    for i, cell in enumerate(nb.get("cells", [])):
        if cell.get("cell_type") != "code":
            continue
        src = "".join(cell.get("source", []))
        src = "\n".join("" if ln.lstrip().startswith(("!", "%")) else ln
                        for ln in src.splitlines())
        for f in scan_python(src, relpath, ctx):
            f.fix = None
            f.details["cell"] = i
            f.key = f"cell{i}|{f.key}"
            out.append(f)
    return out


CLI_TRC = re.compile(r"--trust[-_]remote[-_]code(?![\w-])(?!\s*(=\s*)?(false|False|0)\b)")
KEY_TRC = re.compile(r"""^\s*["']?trust[-_]remote[-_]code["']?\s*[:=]\s*["']?(true|True|yes)""")


def scan_config_text(text: str, relpath: str) -> list[Finding]:
    out = []
    for i, ln in enumerate(text.splitlines(), start=1):
        if ln.lstrip().startswith("#"):
            continue
        if KEY_TRC.search(ln) or CLI_TRC.search(ln):
            out.append(make("AW212", "trust_remote_code enabled: " + ln.strip()[:120], relpath,
                            i, key=ln.strip()))
    return out

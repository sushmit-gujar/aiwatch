"""Model-artifact scanning, delegated to loadsafe (https://github.com/sushmit-gujar/loadsafe)."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding, Severity
from ..rules import make

MODEL_EXT = (".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib", ".npy", ".npz",
             ".safetensors", ".onnx", ".gguf", ".h5", ".keras", ".dill", ".mar")
PICKLE_EXT = (".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".joblib", ".dill", ".mar")


def is_artifact(p: Path) -> bool:
    return p.suffix.lower() in MODEL_EXT


def loadsafe_available() -> bool:
    try:
        import loadsafe.scanner  # noqa: F401
    except ImportError:
        return False
    return True


def scan_artifacts(root: Path, files: list[tuple[Path, str]]) -> tuple[list[Finding], dict]:
    meta: dict = {"engine": None, "files": 0, "bytes": 0}
    if not files:
        return [], meta
    out: list[Finding] = []
    if loadsafe_available():
        import loadsafe
        from loadsafe.findings import Severity as LSev
        from loadsafe.scanner import scan_paths

        meta["engine"] = f"loadsafe {loadsafe.__version__}"
        for p, rel in files:
            rep = scan_paths([str(p)], repo_checks=False, hash_files=False,
                             min_severity=LSev.LOW)
            for a in rep.artifacts:
                meta["files"] += 1
                meta["bytes"] += a.size
                for lf in a.findings:
                    sev = Severity(int(lf.severity))
                    out.append(make("AW209", f"[{lf.rule_id}] {lf.message}", rel, 0,
                                    key=f"{lf.rule_id}|{lf.message}", severity=sev,
                                    loadsafe_rule=lf.rule_id, format=a.format,
                                    location=lf.location))
        return out, meta
    meta["engine"] = "builtin (install aiwatch[artifacts] for loadsafe)"
    for p, rel in files:
        meta["files"] += 1
        meta["bytes"] += p.stat().st_size
        if p.suffix.lower() in PICKLE_EXT:
            out.append(make("AW210", f"{p.suffix} artifact is pickle-based", rel, 0,
                            key=rel))
    return out, meta

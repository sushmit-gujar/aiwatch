"""Rule catalogue with OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS mappings.

Only mappings we consider accurate are listed; a rule with no good LLM Top 10 fit has none.

* OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/llm-top-10/
* MITRE ATLAS: https://atlas.mitre.org/ (technique names as of the 2026 releases)
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Finding, Severity

LLM02 = "LLM02:2025 Sensitive Information Disclosure"
LLM03 = "LLM03:2025 Supply Chain"
LLM04 = "LLM04:2025 Data and Model Poisoning"
LLM05 = "LLM05:2025 Improper Output Handling"
LLM06 = "LLM06:2025 Excessive Agency"

ATLAS_NAMES = {
    "AML.T0010.001": "AI Supply Chain Compromise: AI Software",
    "AML.T0010.003": "AI Supply Chain Compromise: Model",
    "AML.T0010.005": "AI Supply Chain Compromise: AI Agent Tool",
    "AML.T0011.000": "User Execution: Unsafe AI Artifacts",
    "AML.T0011.002": "User Execution: Poisoned AI Agent Tool",
    "AML.T0018.002": "Manipulate AI Model: Embed Malware",
    "AML.T0049": "Exploit Public-Facing Application",
    "AML.T0055": "Unsecured Credentials",
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    default_severity: Severity
    help: str
    owasp: tuple[str, ...] = ()
    atlas: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()


_R = [
    # dependencies ------------------------------------------------------------------------
    Rule("AW100", "Vulnerable dependency (known advisory)", "dependency", Severity.HIGH,
         "Upgrade to the minimal safe version computed by `aiwatch fix`.",
         (LLM03,), ("AML.T0010.001",), ("CWE-1395",)),
    Rule("AW101", "AI/ML dependency is not pinned", "dependency", Severity.LOW,
         "Pin exact versions (or commit a lockfile) so advisories can be matched and builds "
         "are reproducible.", (LLM03,), ("AML.T0010.001",), ("CWE-1357",)),
    Rule("AW102", "Vulnerable MCP server package", "mcp", Severity.HIGH,
         "Pin the MCP server to the minimal safe version.",
         (LLM03,), ("AML.T0010.005",), ("CWE-1395",)),
    # model loading / artifacts -----------------------------------------------------------
    Rule("AW200", "torch.load without weights_only=True", "code", Severity.MEDIUM,
         "torch.load unpickles arbitrary objects unless weights_only=True (default only from "
         "torch 2.6). Set weights_only=True and prefer safetensors.",
         (LLM03, LLM04), ("AML.T0011.000",), ("CWE-502",)),
    Rule("AW201", "Hugging Face download without a pinned revision", "code", Severity.MEDIUM,
         "from_pretrained / hf_hub_download / snapshot_download follow a moving branch. Pin "
         "revision=<commit sha>.", (LLM03,), ("AML.T0010.003",), ("CWE-494",)),
    Rule("AW202", "trust_remote_code=True", "code", Severity.HIGH,
         "Executes Python shipped in the model repo. Avoid, or at least pin revision=<sha> "
         "after reviewing the code.", (LLM03,), ("AML.T0010.003", "AML.T0011.000"), ("CWE-94",)),
    Rule("AW203", "numpy.load with allow_pickle=True", "code", Severity.HIGH,
         "allow_pickle=True lets .npy/.npz files run code. Use allow_pickle=False.",
         (LLM03,), ("AML.T0011.000",), ("CWE-502",)),
    Rule("AW204", "Unsafe deserializer used for model/data", "code", Severity.MEDIUM,
         "pickle / joblib / dill / cloudpickle loads execute code. Use safetensors, skops or "
         "plain JSON for untrusted inputs.", (LLM03,), ("AML.T0011.000",), ("CWE-502",)),
    Rule("AW205", "LangChain dangerous deserialization enabled", "code", Severity.HIGH,
         "allow_dangerous_deserialization=True unpickles the vector-store index. Only load "
         "indexes you built yourself; rebuild otherwise.",
         (LLM03, LLM04), ("AML.T0011.000",), ("CWE-502",)),
    Rule("AW206", "LLM output can execute code or requests", "code", Severity.HIGH,
         "allow_dangerous_code / allow_dangerous_requests lets model output run Python or hit "
         "arbitrary URLs. Sandbox it or remove the flag.",
         (LLM05, LLM06), (), ("CWE-94",)),
    Rule("AW207", "yaml.load without a safe Loader", "code", Severity.MEDIUM,
         "yaml.load with the default/unsafe loader can construct arbitrary objects. Use "
         "yaml.safe_load.", (), (), ("CWE-502",)),
    Rule("AW208", "Gradio app shared publicly", "code", Severity.MEDIUM,
         "launch(share=True) exposes the app via a public *.gradio.live tunnel.",
         (), ("AML.T0049",), ("CWE-668",)),
    Rule("AW209", "Model artifact issue (loadsafe)", "artifact", Severity.HIGH,
         "See the loadsafe rule id in details.", (LLM03, LLM04),
         ("AML.T0010.003", "AML.T0011.000"), ("CWE-502",)),
    Rule("AW210", "Pickle-based model artifact (not deep-scanned)", "artifact", Severity.LOW,
         "Install `aiwatch[artifacts]` (loadsafe) for opcode-level scanning; prefer "
         "safetensors.", (LLM03,), ("AML.T0011.000",), ("CWE-502",)),
    Rule("AW211", "Referenced Hugging Face model ships only pickle weights", "model",
         Severity.MEDIUM, "Prefer a repo/revision with .safetensors weights or convert them.",
         (LLM03,), ("AML.T0010.003", "AML.T0011.000"), ("CWE-502",)),
    Rule("AW212", "trust_remote_code enabled in a config file", "config", Severity.HIGH,
         "Serving configs (vLLM, TGI, app YAML) that trust remote code execute repo Python.",
         (LLM03,), ("AML.T0010.003", "AML.T0011.000"), ("CWE-94",)),
    # MCP -------------------------------------------------------------------------------------
    Rule("AW300", "MCP server package is not version-pinned", "mcp", Severity.MEDIUM,
         "npx/uvx without an exact version runs whatever was published last (rug-pull / "
         "typosquat window). Pin pkg@x.y.z.", (LLM03,), ("AML.T0010.005", "AML.T0011.002"),
         ("CWE-494",)),
    Rule("AW301", "MCP filesystem server granted a broad root", "mcp", Severity.HIGH,
         "Scope filesystem servers to project directories, never / or the home directory.",
         (LLM06,), (), ("CWE-732",)),
    Rule("AW302", "Remote MCP server over plain HTTP", "mcp", Severity.MEDIUM,
         "Use HTTPS for non-local MCP endpoints; tool calls and tokens travel in clear text.",
         (LLM02,), (), ("CWE-319",)),
    Rule("AW303", "MCP server container image not pinned by digest", "mcp", Severity.LOW,
         "Use image@sha256:<digest>.", (LLM03,), ("AML.T0010.004",), ("CWE-494",)),
    Rule("AW304", "MCP server auto-approves tool calls", "mcp", Severity.MEDIUM,
         "alwaysAllow / autoApprove removes the human check on tool calls.",
         (LLM06,), (), ("CWE-862",)),
    # secrets ---------------------------------------------------------------------------------
    Rule("AW400", "Hard-coded credential", "secret", Severity.HIGH,
         "Rotate the key, then load it from the environment or a secret manager.",
         (LLM02,), ("AML.T0055",), ("CWE-798",)),
]

ATLAS_NAMES.setdefault("AML.T0010.004", "AI Supply Chain Compromise: Container Registry")

RULES: dict[str, Rule] = {r.id: r for r in _R}


def make(rule_id: str, message: str, file: str, line: int = 0, *, key: str = "",
         severity: Severity | None = None, **details: object) -> Finding:
    r = RULES[rule_id]
    return Finding(
        rule_id=r.id,
        severity=severity if severity is not None else r.default_severity,
        title=r.title,
        message=message,
        file=file,
        line=line,
        category=r.category,
        key=key,
        details=dict(details),
        owasp=r.owasp,
        atlas=r.atlas,
        cwe=r.cwe,
    )

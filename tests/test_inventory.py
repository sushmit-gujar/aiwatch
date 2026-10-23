import ast

from aiwatch.inventory import deps
from aiwatch.inventory.code import CodeContext, scan_config_text, scan_notebook, scan_python
from aiwatch.inventory.mcp import scan_mcp
from aiwatch.inventory.secrets import scan_secrets
from aiwatch.models import Fix
from aiwatch.remediate.fixer import _apply_text

from .conftest import make_db


def test_requirements_parsing_and_spans():
    text = ("# c\ntorch==2.5.1  # pinned\nuvicorn[standard]==0.27.0 ; python_version>'3.8'\n"
            "openai>=1.0\n-r other.txt\nnumpy==1.26.* \nfoo==1.0 --hash=sha256:abc\n")
    cs = deps.parse_requirements(text, "requirements.txt")
    by = {c.name: c for c in cs}
    assert by["torch"].version == "2.5.1" and by["torch"].line == 2
    assert text[slice(*by["torch"].span)] == "2.5.1"
    assert by["uvicorn"].version == "0.27.0" and text[slice(*by["uvicorn"].span)] == "0.27.0"
    assert by["openai"].version is None and by["numpy"].version is None
    assert by["foo"].version == "1.0"


def test_pyproject_pep621_and_poetry():
    raw = ('[project]\ndependencies=["llama-index==0.9.0","fastapi>=0.1"]\n'
           '[project.optional-dependencies]\nx=["vllm==0.5.0"]\n'
           '[tool.poetry.dependencies]\npython="^3.10"\ngradio="4.19.0"\nmlflow="^2.9"\n')
    cs = {c.name: c for c in deps.parse_pyproject(raw, "pyproject.toml")}
    assert cs["llama-index"].version == "0.9.0" and raw[slice(*cs["llama-index"].span)] == "0.9.0"
    assert cs["vllm"].version == "0.5.0" and cs["fastapi"].version is None
    assert cs["gradio"].version == "4.19.0" and raw[slice(*cs["gradio"].span)] == "4.19.0"
    assert cs["mlflow"].version is None


def test_lockfiles():
    uv = '[[package]]\nname = "torch"\nversion = "2.5.1"\n\n[[package]]\nname = "app"\n' \
         'version = "0.1"\nsource = { editable = "." }\n'
    cs = deps.parse_toml_lock(uv, "uv.lock", "uv.lock")
    assert [(c.name, c.version, c.direct) for c in cs] == [("torch", "2.5.1", False)]
    pl = deps.parse_pipfile_lock('{"default":{"Jinja2":{"version":"==3.1.2"}}}', "Pipfile.lock")
    assert pl[0].name == "jinja2" and pl[0].version == "3.1.2"


def _ctx(tmp_path, hf=None, torch_safe=False):
    return CodeContext(None, make_db(tmp_path, hf=hf or {}), torch_safe)


def _fixed(src, findings):
    edits = [e for f in findings if f.fix for e in f.fix.edits]
    out = _apply_text(src, edits)
    ast.parse(out)
    return out


def test_python_rules_and_fixes(tmp_path):
    src = (
        "import torch as t\nimport numpy as np\nimport yaml\nimport pickle\n"
        "from transformers import AutoModel\n"
        "m = AutoModel.from_pretrained('org/model', trust_remote_code=True)\n"
        "x = t.load('a.pt')\ny = t.load('b.pt', weights_only=False)\n"
        "z = np.load('c.npy', allow_pickle=True)\ncfg = yaml.load(open('c.yml'))\n"
        "d = pickle.loads(b'')\nagent(allow_dangerous_code=True)\n"
        "ui.launch(share=True)\n"
        "ok = AutoModel.from_pretrained('org/model', revision='" + "a" * 40 + "')\n"
        "local = AutoModel.from_pretrained('./ckpt')\n"
        "safe = yaml.load(open('c.yml'), Loader=yaml.SafeLoader)\n"
    )
    hf = {"org/model": {"id": "org/model", "sha": "b" * 40, "weights": ["pytorch_model.bin"],
                        "gated": False}}
    fs = scan_python(src, "app.py", _ctx(tmp_path, hf))
    rules = sorted(f.rule_id for f in fs)
    assert rules == ["AW200", "AW200", "AW201", "AW202", "AW203", "AW204", "AW206", "AW207",
                     "AW208", "AW211", "AW211"]
    out = _fixed(src, fs)
    assert f"trust_remote_code=True, revision=\"{'b' * 40}\")" in out
    assert "t.load('a.pt', weights_only=True)" in out
    assert "t.load('b.pt', weights_only=True)" in out
    assert "allow_pickle=False" in out and "yaml.safe_load(open('c.yml'))" in out
    assert "share=False" in out
    # second pass: the fixed code no longer triggers the fixed rules
    again = sorted(f.rule_id for f in scan_python(out, "app.py", _ctx(tmp_path, hf)))
    assert "AW201" not in again and "AW200" not in again and "AW203" not in again
    trc = [f for f in scan_python(out, "app.py", _ctx(tmp_path, hf)) if f.rule_id == "AW202"]
    assert trc and trc[0].severity.label == "medium"  # pinned now -> downgraded


def test_torch_default_safe_downgrades(tmp_path):
    fs = scan_python("import torch\ntorch.load('x')\n", "a.py", _ctx(tmp_path, torch_safe=True))
    assert fs[0].severity.label == "low"


def test_multiline_call_fix_and_unicode(tmp_path):
    src = "import torch\n# naïve ünïcode\nx = torch.load(\n    'é.pt',\n    map_location='cpu',\n)\n"
    fs = scan_python(src, "a.py", _ctx(tmp_path))
    out = _fixed(src, fs)
    assert "map_location='cpu', weights_only=True,\n)" in out


def test_notebook_and_config_text(tmp_path):
    nb = '{"cells":[{"cell_type":"code","source":["!pip install x\\n","import torch\\n",' \
         '"torch.load(\'m.pt\')"]}]}'
    fs = scan_notebook(nb, "nb.ipynb", _ctx(tmp_path))
    assert [f.rule_id for f in fs] == ["AW200"] and fs[0].fix is None
    cfg = scan_config_text("model:\n  trust_remote_code: true\n# trust_remote_code: true\n"
                           "cmd: vllm serve m --trust-remote-code\nx: --trust-remote-code=false\n",
                           "c.yaml")
    assert [f.line for f in cfg] == [2, 4]


def test_mcp_rules(tmp_path):
    text = """{
  // jsonc comment
  "mcpServers": {
    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "~"]},
    "x": {"command": "npx", "args": ["-y", "some-server@latest"], "autoApprove": ["run"]},
    "py": {"command": "uvx", "args": ["--from", "mcp-server-git==2025.7.1", "mcp-server-git"]},
    "d": {"command": "docker", "args": ["run", "-i", "ghcr.io/org/img:1.0"]},
    "r": {"url": "http://remote.example.org/mcp"},
    "l": {"url": "http://localhost:3000/mcp"},
  }
}"""
    db = make_db(tmp_path, npm_latest={"some-server": "1.2.3"})
    fs, cs = scan_mcp(text, ".vscode/mcp.json", db)
    assert sorted(f.rule_id for f in fs) == ["AW300", "AW301", "AW302", "AW303", "AW304"]
    assert {(c.ecosystem, c.name, c.version) for c in cs} == {
        ("npm", "@modelcontextprotocol/server-filesystem", "0.6.2"),
        ("PyPI", "mcp-server-git", "2025.7.1")}
    pin = next(f for f in fs if f.rule_id == "AW300")
    assert isinstance(pin.fix, Fix)
    out = _apply_text(text, pin.fix.edits)
    assert '"some-server@1.2.3"' in out
    c = next(c for c in cs if c.ecosystem == "npm")
    assert text[slice(*c.span)] == "0.6.2"


def test_secrets_masked_and_placeholders_ignored():
    key = "sk-proj-" + "Ab3" * 10
    hf = "hf_" + "Q" * 34
    text = f'OPENAI_API_KEY="{key}"\nHF={hf}\nOPENAI_API_KEY=sk-your-key-here-xxxxxxxxxxxxxxxx\n'
    fs = scan_secrets(text, ".env")
    assert [f.details["kind"] for f in fs] == ["OpenAI API key", "Hugging Face token"]
    assert key not in str([f.to_dict() for f in fs])

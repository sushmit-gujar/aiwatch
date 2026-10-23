# vulnerable-llm-app (deliberately insecure demo fixture)

**Do not deploy. Do not install these requirements.** This folder exists only so
`aiwatch` has something real to find and fix. It is never executed by tests or CI.

- `requirements.txt` / `serving/pyproject.toml` pin old releases of torch, transformers,
  langchain, llama-index, vllm, mlflow, gradio, mcp and friends that have real, public
  advisories in OSV.dev.
- `app/*.py` contain common insecure AI-loading patterns (unpinned Hugging Face revisions,
  `trust_remote_code=True`, `torch.load` without `weights_only=True`, `allow_pickle=True`,
  LangChain `allow_dangerous_*` flags, `yaml.load`, Gradio `share=True`).
- `.cursor/mcp.json` has MCP servers with vulnerable / unpinned versions, a filesystem
  server rooted at `/`, plain-HTTP remote endpoint and auto-approval.
- `models/classifier.pkl` is a **harmless** proof-of-concept pickle: if loaded it only calls
  `print(...)`. It demonstrates what loadsafe detects.
- The API key in `.cursor/mcp.json` and `.env` is fake (`...DEMOnotARealKey...`).

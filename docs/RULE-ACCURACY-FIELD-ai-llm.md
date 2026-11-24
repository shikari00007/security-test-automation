# Field accuracy: ai-llm rules (SEC-AI-001, 002, 003, 004)

All three rules are `maturity: experimental`. This is a small, honest sample, not a precision/recall estimate.

## Method

- Inputs (static text only, never executed): shallow clones (`git clone --depth 1`) in `/tmp/field-ai` of `modelcontextprotocol/servers`, `langchain-ai/langchain`, `run-llama/llama_index`, `openai/openai-agents-python`, `openai/openai-cookbook`. No LLM packages with example code were found in the local site-packages (the pip-listed `openai` package had no importable directory).
- Command per repository: `python3 -m security_runner audit <dir> --type ai-llm --output-dir /tmp/acc-ai/<name> --fail-on never --no-verify`.
- Each finding was read in context. Verdicts: TP (real weakness), FP (not a weakness), and why.

## Results before fixes

| Rule | Repos with findings | Findings | TP | FP |
|---|---|---|---|---|
| SEC-AI-001 | 0 | 0 | 0 | 0 |
| SEC-AI-002 | 0 | 0 | 0 | 0 |
| SEC-AI-003 | 1 (openai-agents-python) | 21 | 0 | 21 |

The only `.mcp.json` files in the corpus (langchain, mcp servers, cookbook plugin) point at remote HTTP documentation servers with no launcher or credentials, so SEC-AI-002 had nothing to flag; this is a thin sample for that rule.

## Triage of the 21 SEC-AI-003 findings (all FP)

| Group | Count | Why FP | Action |
|---|---|---|---|
| Test files (`tests/**`) with stub `ShellTool(executor=lambda ...)` | 13 | Mocks inside unit tests, not deployed agent wiring. Several reported lines were not even the tool call: the shared `android.strip_hash` regex (`^\s*#.*$`) swallowed preceding blank lines and shifted line numbers. | Skip test paths; use a local line-preserving comment stripper (`ai_llm.strip_hash`). |
| `examples/tools/shell.py`, `local_shell_skill.py` (3 sites) | 3 | Human approval is implemented with `needs_approval=True` / `on_approval=...`, which the approval regex did not know. | Extend the approval identifiers. |
| Hosted-container shell with `container_auto`/`container_reference` and network disabled (4 sites) and `workspace_shell.py` (sandbox session) | 5 | Execution is in an isolated container/sandbox, not on the host. | Treat sandbox/container markers in the file as mitigation for shell/REPL tools (not for danger flags). Explicit `sandbox = False` still flags. |

After the fixes the five repositories produce 0 findings for all three rules. This means the rules are quiet on this sample; it does **not** show they detect real issues in it. No true positive was observed in the field.

## Known false negatives seen in the field (not fixed; documented limits)

- `llama-index-program-evaporate` `extractor.py` executes LLM-generated code with `exec(fn_str, sandbox)` where `fn_str` arrives as a function parameter. Taint is not tracked across functions, so SEC-AI-001 is silent. (The code does validate and restrict builtins, so this is not necessarily a vulnerability.)
- `openai-cookbook` `python_code_interpreter_tool.py` runs model-supplied tool arguments through `docker exec ... python -c exec(...)`. Tool-call arguments are not treated as taint sources by SEC-AI-001 (it is also containerised).
- The cookbook has about 1000 Jupyter notebooks; `.ipynb` files are not scanned by any AI rule.
- SEC-AI-003 recognises only a fixed list of dangerous tool classes and flags; other frameworks' equivalents are invisible.

## Residual risks of the current heuristics

- File-level approval or sandbox markers can suppress a real finding when another tool in the same file is unguarded.
- Allow-list detection is name-based (`ALLOWED*`, `SAFE*`, `allow*`).
- Triage sample size: 21 SEC-AI-003 findings (all examined), 0 for the other rules. Reviewers should not infer precision for SEC-AI-001/002 from this document; use `fixtures/accuracy/ai-llm/cases.json` (synthetic adversarial cases, 74 in total across SEC-AI-001..004) as the only evidence for those.

## Update after independent review

The rules were tightened (function-scoped approval/sandbox markers, exact-pin semantics for MCP launchers, SQL quoted f-string detection, no name-based sanitisation) and SEC-AI-004 was added. All five repositories were re-audited: 0 findings for all four rules. Differences: `workspace_shell.py` is still quiet because the sandbox identifier is in the same class; SEC-AI-004 produced no findings. Three persisted-state `pickle.load`/`torch.load` sites in llama-index integrations (txtai, bge_m3, embeddings-adapter) are local loads without a download in the function and are deliberately not flagged (possible false negatives if the persist directory is attacker-writable). Still no true positive was observed, so field precision for SEC-AI-001/002/004 remains unmeasured; their confidence is `low` in metadata.

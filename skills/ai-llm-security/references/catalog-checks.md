# Catalog checks for ai-llm

Reviewed, executable checks. Load on demand; do not copy the catalog into prompts.

- List: `security-skills catalog checks ai-llm`
- Browse the larger normalized catalog: `security-skills catalog list --domain ai-llm --category <category> --limit 20`
- Without the CLI use the methodology reference; all checks there are manual.

Snapshot of reviewed check IDs when this skill was built (the CLI is authoritative):

| ID | Mode | Severity | Title |
|---|---|---|---|
| SEC-AI-001 | static | high | Model output flows to eval/exec/shell/SQL sinks |
| SEC-AI-002 | static | high | MCP/agent config with unpinned packages, root filesystem exposure or inline tokens |
| SEC-AI-003 | static | high | Agent tools enabling shell/Python REPL/dangerous code without approval |
| SEC-AI-004 | static | medium | Model artifact loading: trust_remote_code=True, pickle-family or unsafe torch.load of downloaded data |
| SEC-AI-050 | dynamic | high | Prompt injection and indirect injection evaluation |
| SEC-AI-051 | hybrid | high | RAG data-boundary and tenant isolation test |

Maturity: SEC-AI-001/002/003/004 are `experimental` static heuristics (heuristic, precision not established; synthetic accuracy cases only plus a small field sample, see `docs/RULE-ACCURACY-FIELD-ai-llm.md`). SEC-AI-001, 003 and 004 have `low` confidence. SEC-AI-050/051 are planned, `unimplemented`, and have no executor. No reviewed check exists for RAG, secrets in prompts, rate limiting or prompt leakage: treat those as manual. The developer methodology is `docs/methodology/ai-llm.md` (REVIEWED WITH CHANGES - experimental).

What the static rules do and do not see:

- All rules skip paths under `tests/`, `test/`, `__tests__/`, `__mocks__/` and test-named files.
- SEC-AI-001: Python/JS/TS only; per-function taint from LLM SDK calls to eval/exec/shell/SQL sinks; partial SQL coverage; names alone never sanitise; not HTML sinks, not tool-call arguments, not cross-function flows.
- SEC-AI-002: structured JSON MCP configs (file name contains `mcp`, or `claude_desktop_config.json`); YAML only by one-line `npx -y`/`uvx` text and vendor-prefixed tokens (structured YAML not parsed); `.claude/settings.json` not scanned. Only exact versions, 40-hex SHAs and integrity hashes are pinned: ranges (`^ ~ >= *`) and dist-tags (`latest`, `next`, `beta`) are reported. Filesystem scope covers exact roots only; secrets: vendor prefixes, secret-named env keys, Bearer.
- SEC-AI-003: fixed list of dangerous tools/flags; shell/REPL tools are quiet only when approval or isolation markers sit in the same function (or class); markers set to off values do not count; JSON agent configs and shell scripts are not scanned.
- SEC-AI-004: `trust_remote_code=True`, pickle-family loads and `torch.load` without `weights_only` (only when the function downloads data), `weights_only=False`.

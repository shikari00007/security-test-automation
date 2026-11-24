# AI / LLM application security methodology (developer-focused)

**Status: REVIEWED WITH CHANGES - experimental.** An independent review (`docs/methodology/ai-llm-REVIEW.md`) was applied; see its Resolution section. Automated checks remain `maturity: experimental`.
This document is original work. No AI/LLM checklist was supplied to the project, and nothing here is copied from a third-party checklist. Standards mappings (OWASP Top 10 for LLM Applications, 2025 edition, and CWE) are given only where the match is believed accurate and were checked by the reviewer; remaining judgement calls are marked approximate.

Audience: developers and reviewers of applications that embed LLMs, agents, RAG pipelines or MCP servers.
Scope of automation: four experimental static checks (SEC-AI-001/002/003/004), all low-to-medium confidence heuristics. Two further checks (SEC-AI-050, SEC-AI-051) are planned and have no executor. Everything else is manual review.

## How to read each topic

- **Review**: what to inspect in code and configuration.
- **Static signals**: what a text/AST scan can plausibly see. **Needs dynamic/manual**: what only behaviour or design review reveals.
- **Secure behaviour**: the property a reviewer should be able to confirm.
- **Mapping**: OWASP LLM Top 10 (2025) and CWE, only where accurate.
- **Coverage**: reviewed check ID, planned ID, or "no automation".

## Global limitations

0. The static rules skip any path under `tests/`, `test/`, `__tests__/` or `__mocks__/` and files named `test_*.py`, `*_test.py`, `conftest.py`, `*.test.*`, `*.spec.*`.
1. Static checks are line-oriented heuristics (Python, JavaScript/TypeScript, MCP JSON/YAML). They do not model inter-procedural data flow, frameworks' implicit wiring, other languages, or runtime configuration (environment, remote config, feature flags).
2. A pass means "this heuristic did not fire", never "this category is secure". Prompt injection cannot be excluded by code reading; the model's behaviour is not statically decidable.
3. Model behaviour is non-deterministic; any dynamic evaluation yields evidence of a failure, not proof of absence. Results depend on model version, temperature and prompt.
4. Dynamic work needs written scope, an isolated environment and synthetic data (see `skills/ai-llm-security/references/safety-and-states.md`). It is not performed by the runner today.
5. Standards mappings are approximate. OWASP LLM categories describe risk classes, not testable requirements; CWE has few LLM-specific entries.
6. All AI checks are `maturity: experimental`; their precision and recall are only measured on the synthetic cases in `fixtures/accuracy/ai-llm/` and the field sample in `docs/RULE-ACCURACY-FIELD-ai-llm.md`.

---

## 1. Trust boundaries

**Concept.** An LLM prompt is a single text channel in which instructions and data are indistinguishable to the model. Identify four sources and treat all but the first as untrusted:

| Source | Trust | Examples |
|---|---|---|
| System/developer prompt | Trusted (but not secret, see 10) | templates in the repo |
| User input | Untrusted, authenticated identity may be known | chat messages, uploaded files |
| Retrieved content | Untrusted, may be attacker-writable | RAG chunks, web pages, tickets, emails, wiki |
| Tool/MCP output and tool descriptions | Untrusted unless the tool and its data source are both under your control | search, browser, issue trackers, third-party MCP servers |

**Review.** Draw the data-flow: every path by which text reaches the prompt, and every path by which model output reaches a tool, store, renderer or other user. Mark where authorization decisions are made and confirm they are made by code, not by the model.
**Static signals.** Prompt templates with string interpolation of request fields or retrieved text (weak signal; legitimate and common). Frameworks' loaders that fetch URLs or files into prompts.
**Needs manual.** Whether a boundary is actually enforced; who can write into the retrieved corpus.
**Secure behaviour.** Authorization, tenant scoping and parameter validation are enforced outside the model on every tool call; the prompt is never an access-control mechanism.
**Mapping.** LLM01 (context), LLM06. CWE: none specific (CWE-1427 applies to a concrete injection weakness, not to the architecture).
**Coverage.** No automation (design review). Dynamic confirmation planned under SEC-AI-050.

## 2. Direct and indirect prompt injection

**Review.** Where instructions and data share a prompt; whether untrusted content can reach a prompt that has tools or sensitive context. Indirect injection (payload in a retrieved document, web page, email, tool result, image text) matters most when the same context can also call tools or render links/images.
**Static signals.** Weak: retrieval or web-fetch results concatenated into a prompt in a function that also registers tools. Not reliably detectable.
**Needs dynamic/manual.** Run a repeatable injection suite with benign canary instructions against an isolated deployment with stubbed or lab model; test via every ingestion channel, including multi-step agent loops.
**Secure behaviour.** Injected text can at worst produce wrong prose; it cannot trigger a privileged tool call, exfiltrate data (including via rendered URLs/markdown images), or change authorization. Defence is architectural (least privilege, approval, output encoding, egress limits); delimiters, "ignore instructions" prompts and classifier filters are mitigations, not controls.
**Mapping.** LLM01 Prompt Injection. CWE-1427 (Improper Neutralization of Input Used for LLM Prompting) fits direct injection well; for indirect injection or jailbreaking the CWE notes the root cause may differ, so the mapping is stated as approximate there.
**Coverage.** Planned SEC-AI-050 (dynamic, unimplemented). No static automation.

## 3. Insecure output handling

**Review.** Every sink that consumes model output: `eval`/`exec`, `Function`, `vm`, shell/`subprocess`, SQL/ORM raw queries, template engines, HTML rendering (including markdown to HTML), file paths, URLs fetched server-side, deserializers, downstream APIs.
**Static signals.** Variable assigned from an LLM SDK call (or derived from it) used as argument to those sinks (SEC-AI-001). Raw string SQL built from such a variable. `innerHTML`/`dangerouslySetInnerHTML`/`|safe` with model text (not covered).
**Needs manual.** Validation that happens in helper functions, other modules or other languages; whether a sink is actually reachable with attacker-influenced text.
**Secure behaviour.** Model output is parsed against a schema, mapped to an allow-list of actions, parameterised in queries, HTML-escaped (or sanitised) on render, and never executed. Code-execution features run in a sandbox without secrets or network.
**Mapping.** LLM05 Improper Output Handling. Primary: CWE-1426 (Improper Validation of Generative AI Output). Downstream consequences: CWE-94 (code injection), CWE-78 (OS command injection), CWE-89 (SQL injection), CWE-79 (XSS, for HTML sinks).
**Coverage.** SEC-AI-001 for eval/exec/shell/SQL in Python and JS/TS. HTML/XSS sinks, file paths and SSRF: no automation. Limitations: single-file, per-function heuristic taint. A variable's *name* (`safe`, `allowed`) is never treated as sanitisation. Only an enforced membership test (`if x not in ALLOWED: raise`, `if x in ALLOWED:` guarding a non-empty block, `assert`, JS `ALLOWED.includes(x)`) or a direct lookup (`ALLOWED[x]`, `.get(x)`) against an allow-list-named container, and cast/quote wrappers (`int`, `float`, `shlex.quote`, `re.escape`, `parseInt`, `Number`), clear taint. SQL detection is partial: `execute(f"...{x}...")` including quoted placeholders, concatenation, `%`, `.format` and template literals on the call line or via an intermediate variable; ORMs and query builders are not modelled. Known false negatives: for-loop targets, flows through function parameters/returns/classes, tool-call arguments as sources, `innerHTML`/`Markup`/`|safe`, other languages, a validator that lives in another function. Argument-injection with list argv (`subprocess.run(['echo', x])`) is still reported and is probably a false positive for shell execution.

## 4. Excessive agency and tool authorization

**Review.** The list of tools/functions registered with each agent: capability (read vs write vs execute), credentials used (per-user or one shared service account), argument validation, rate/ cost limits, and which actions require a human decision.
**Static signals.** Shell/Python-REPL tools, `allow_dangerous_code=True`, `dangerouslyAllowBrowser: true`, `auto_approve: true`, `human_in_the_loop: false`, `--dangerously-skip-permissions` in agent configs (SEC-AI-003).
**Needs manual.** Whether a tool re-checks the end user's permission server-side; breadth of a "generic" HTTP/SQL/file tool; whether approval is meaningful (informed, not click-through) and cannot be bypassed by the model; sandbox quality.
**Secure behaviour.** Least privilege per tool and per user; allow-lists for commands, hosts, paths and tables; destructive or irreversible actions (send, pay, delete, deploy) require human approval showing the actual arguments; credentials are scoped to the requesting user; tool calls are logged.
**Mapping.** LLM06 Excessive Agency. CWE-250 (unnecessary privileges) and CWE-94 for code-execution tools; CWE-285/862 for missing tool-level authorization (not automated).
**Coverage.** SEC-AI-003 (low confidence; limited to a fixed list of dangerous tool classes and flags). Flags such as `allow_dangerous_code=True`, `auto_approve: true`, `--dangerously-skip-permissions` are reported unconditionally. For shell/REPL tool classes an approval marker (`needs_approval`, `interrupt_before`, `HumanApprovalCallbackHandler`, ...) or an explicit isolation token (`*Sandbox*` identifiers, `sandbox=True`, `docker`, `container_auto`, `network_policy`, ...) must appear in the same function (or class, for methods), not merely in the file; markers assigned an off value (`require_approval = False`, `sandbox_mode = 'none'`) and imports do not count. JSON agent configs (`.claude/settings.json`, `autoApprove` keys) and shell scripts are not scanned. Tool-level authorization: no automation (dynamic test planned within SEC-AI-050). Approval dialogs should (SHOULD, not MUST) show the actual arguments.

## 5. MCP and agent configuration

**Review.** Every MCP server entry in `.mcp.json`, editor/desktop configs and agent YAML: how it is launched, what it can reach, what credentials it holds, and whether its tool descriptions and outputs are trusted.
**Static signals (SEC-AI-002).** `npx -y`/`bunx`/`uvx` launching a package without a version pin; filesystem server rooted at `/`, `~`, home or system dirs; literal tokens in `env`, `headers` or `args`.
**Needs manual.** Whether a pinned version is itself trustworthy (typosquats, compromised maintainers); network egress scope of the server; whether the server enforces per-user authorization; **tool poisoning** (malicious instructions in tool descriptions or in "rug-pull" updates after approval); cross-server data leakage when one agent connects to several servers; remote (Streamable HTTP, or legacy SSE) servers' authentication. "Tool poisoning" and "rug pull" are attack classes named in published security research (e.g. Invariant Labs, 2025), not terms of the MCP specification. The specification's tools section says clients must treat tool annotations as untrusted unless they come from a trusted server and SHOULD keep a human in the loop for tool invocations. The MCP Security Best Practices page (local MCP server compromise: show the exact command and require explicit consent before launching a local server; token passthrough; confused deputy; SSRF) is normative guidance for server authors and client implementers and motivates the pinning guidance here.
**Secure behaviour.** Servers pinned to exact versions (ideally with lockfile/hash) and reviewed; filesystem/network scope limited to what the task needs; credentials injected from environment or a secret manager, short-lived and least-privilege; tool descriptions are reviewed and re-reviewed on change; untrusted servers are not combined with servers holding sensitive data in one context.
**Mapping.** LLM03 Supply Chain, LLM06 Excessive Agency. CWE-829 (inclusion of functionality from an untrusted control sphere), CWE-798 (hard-coded credentials), CWE-250 (execution with unnecessary privileges; fits a filesystem server given `/` or a home directory; CWE-668 is an alternative).
**Coverage.** SEC-AI-002 for the signals above. Only exact versions (`name@1.2.3`, `name==1.2.3`), 40-hex commit SHAs and integrity hashes count as pinned; ranges (`^ ~ > < * x`), major-only versions and dist-tags (`latest`, `next`, `beta`) are reported as "not exactly pinned". Scope: structured JSON configs with `mcpServers`/`servers`/`mcp_servers` in files whose name contains `mcp` (and `claude_desktop_config.json`); YAML is matched only by one-line `npx -y pkg` / `uvx pkg` text and inline vendor-prefixed tokens (structured YAML is not parsed); `.claude/settings.json` and `.claude.json` are not scanned. Filesystem scope covers only exact roots (`/`, `~`, `/home`, `/Users`, `/etc`, `/root`, `$HOME`, `C:\`) for servers named or args containing `filesystem`. Secret detection covers secret-named env keys with values of 8+ characters, vendor prefixes (`ghp_`, `sk-`, `AKIA`, ...) and `Bearer`; it misses connection-string passwords, `user:pass@` URLs, Basic auth and `--token=` args. Docker `:latest`, `curl | sh` and plain-http remote URLs are out of scope. Tool poisoning, network scope and remote-server authentication: no automation.

## 6. Retrieval-augmented generation

**Review.** Ingestion pipeline (who can add documents, from where), vector store query code, metadata/ACL fields, how citations are generated and displayed.
**Static signals.** Vector store queries without a filter argument derived from the caller; one shared collection/index for all tenants; indexing of documents without carrying source ACL metadata. All are weak and framework-specific.
**Needs dynamic/manual.** Multi-tenant canary test: tenant A retrieves/cites tenant B's synthetic document; document-level ACL changes propagate to the index; poisoned documents containing instructions; citations point to the real retrieved source and a user is authorised to open it.
**Secure behaviour.** Tenant and entitlement filters are applied in the store query (not by post-filtering in the prompt or asking the model); index writes are access-controlled and auditable; retrieved provenance is logged; citations are generated from retrieval metadata, not model free text.
**Mapping.** LLM08 Vector and Embedding Weaknesses, LLM02 Sensitive Information Disclosure, LLM04 Data and Model Poisoning. CWE-639 (authorization bypass via user-controlled key) and CWE-200, approximate; CWE-285/862 may fit a missing tenant filter better.
**Coverage.** Planned SEC-AI-051 (hybrid, unimplemented). No static automation today.

## 7. Secrets and PII in prompts and logs

**Review.** What is placed in prompts (credentials, internal config, other users' data), what is logged (full prompts/responses, tool arguments), retention at the model provider, and trace/observability exports.
**Static signals.** Hard-coded API keys for LLM providers in source (covered by the project's generic secrets checks, not by SEC-AI rules); prompts built from environment variables or config containing secrets; full-prompt logging statements. Only the first is reliably detectable.
**Needs manual.** Provider data-retention/training settings; redaction effectiveness; whether PII reaching the model is necessary and permitted.
**Secure behaviour.** Secrets never enter prompts; PII is minimised/redacted before the model and in logs; logs have access control and retention limits; provider settings match policy.
**Mapping.** LLM02 Sensitive Information Disclosure. CWE-532 (sensitive information in log files), CWE-798 for hard-coded keys.
**Coverage.** No SEC-AI rule. MCP inline tokens are covered by SEC-AI-002 only in MCP configs.

## 8. Model and artifact supply chain

**Review.** How models, tokenizers, adapters and datasets are obtained and loaded.
**Static signals.** `trust_remote_code=True`; `pickle`/`cPickle`/`dill`/`cloudpickle`/`joblib` loads in a function that also downloads data; `torch.load(..., weights_only=False)`, or `torch.load` without `weights_only` on downloaded data (the default is version dependent: PyTorch 2.6 made `weights_only=True` the default, earlier versions did not); `from_pretrained(...)` without a pinned `revision` (commit hash; a branch name is not a pin); downloading weights at runtime from mutable URLs; unpinned ML dependencies. Only the first four are detected (SEC-AI-004).
**Needs manual.** Provenance and licence of models, hash/signature verification, whether safetensors or another non-executable format is used, scanning of artifacts.
**Secure behaviour.** Non-executable formats (e.g. safetensors) preferred. Note safetensors removes code execution on load but not model poisoning or backdoored weights (LLM04), and other formats (executable layers, parser bugs in GGUF/ONNX readers) carry their own risks. Pickle-based formats loaded only from trusted, integrity-checked sources. `weights_only=True` is a mitigation, not an absolute guarantee: CVE-2025-32434 (checked against NVD on 2026-11-20) is an RCE in PyTorch `torch.load` with `weights_only=True` in versions 2.5.1 and prior, patched in 2.6.0, so require PyTorch >= 2.6.0 as well. Remote code disabled or pinned to a reviewed 40-hex revision; artifacts pinned by hash.
**Mapping.** LLM03 Supply Chain. CWE-502 (deserialization of untrusted data) for pickle loading; CWE-829 for remote code; CWE-494 (download of code without integrity check), approximate.
**Coverage.** SEC-AI-004 (experimental, confidence low): `trust_remote_code=True`; pickle-family loads and `torch.load` without `weights_only` only when the same function also downloads data; `torch.load(weights_only=False)`. Not detected: local persisted-state pickles (deliberately, to limit noise), unpinned `revision`, mutable URLs, torch version checks. Hash verification and licence/provenance: manual.

## 9. Denial of wallet and rate limiting

**Review.** Per-user and per-tenant request limits, `max_tokens`/context caps, tool-call loop limits, retry policies, file size limits for ingestion, budgets and alerts on provider spend.
**Static signals.** Weak: absence of `max_tokens`, loops around LLM calls without an iteration bound, unauthenticated endpoints that call a model. Absence-based checks have high false-positive rates and are not automated.
**Needs manual.** Actual limits at the gateway/provider; recursive agent behaviour. Load or DoS tests are out of scope and prohibited by the project's safety gates.
**Secure behaviour.** Authenticated, rate-limited endpoints; bounded tokens, steps and parallelism; spend alerts and hard budget caps.
**Mapping.** LLM10 Unbounded Consumption. CWE-770 (allocation of resources without limits or throttling) and CWE-400 (uncontrolled resource consumption), approximate.
**Coverage.** No automation.

## 10. System-prompt leakage

**Review.** Contents of system prompts: credentials, internal URLs, business rules, authorization logic.
**Static signals.** Secret-like strings in prompt templates (generic secret scanners may catch these).
**Needs manual/dynamic.** Whether extraction of the prompt is possible (it generally should be assumed to be); whether disclosure would matter.
**Secure behaviour.** The system prompt contains nothing whose disclosure is harmful; security rules are enforced in code.
**Mapping.** LLM07 System Prompt Leakage. CWE-200/CWE-798 depending on content.
**Coverage.** No automation.

## 11. Logging, monitoring and evaluation

**Review.** Whether tool calls, approvals, retrieval provenance, refusals and guardrail triggers are logged with user identity; whether an injection/regression suite runs against releases; incident response for model misbehaviour.
**Static signals.** Presence of eval/red-team suites in the repository (informational).
**Needs manual.** Log completeness versus logging of sensitive content (tension with topic 7).
**Secure behaviour.** Security-relevant events are attributable and retained; evaluation suite is repeatable and versioned with model/prompt versions.
**Mapping.** Supports LLM01/LLM06 detection; no direct OWASP LLM category. CWE-778 (insufficient logging), approximate.
**Coverage.** No automation.

---

## Coverage summary

| Topic | OWASP LLM 2025 | Check |
|---|---|---|
| 1 Trust boundaries | LLM01/LLM06 | no automation |
| 2 Prompt injection | LLM01 | SEC-AI-050 (planned) |
| 3 Output handling | LLM05 | SEC-AI-001 (experimental) |
| 4 Excessive agency | LLM06 | SEC-AI-003 (experimental); tool authz no automation |
| 5 MCP/agent config | LLM03, LLM06 | SEC-AI-002 (experimental); tool poisoning no automation |
| 6 RAG | LLM08, LLM02, LLM04 | SEC-AI-051 (planned) |
| 7 Secrets/PII | LLM02 | no automation |
| 8 Model supply chain | LLM03 | SEC-AI-004 (experimental, partial) |
| 9 Denial of wallet | LLM10 | no automation |
| 10 Prompt leakage | LLM07 | no automation |
| 11 Logging/eval | - | no automation |

LLM09 Misinformation is not treated as a security topic here except where unverified output drives privileged actions (see 3 and 4).

## Review decisions (resolved questions)

1. CWE mappings: CWE-1427 accepted; CWE-1426 added as primary for output handling; CWE-250 replaces CWE-732 for MCP scope; CWE-494 stays approximate (CWE-502 primary for pickle, CWE-829 for remote code); CWE-400 added next to CWE-770.
2. Version ranges are not pins for MCP launchers. Only exact versions, 40-hex SHAs and integrity hashes are.
3. File-wide approval/sandbox suppression in SEC-AI-003 was too lenient and was replaced by function/class-scoped markers with off-value handling.
4. SEC-AI-004 added as experimental, low confidence. Safe forms: `weights_only=True` on PyTorch >= 2.6.0, safetensors, 40-hex `revision`, `trust_remote_code=False`.
5. HTML/XSS sinks are not part of SEC-AI-001 (they would be a separate rule, e.g. a future SEC-AI-005); file-path and SSRF sinks stay manual.
6. "Approval must show the actual arguments" is a SHOULD (the MCP specification also uses SHOULD for human-in-the-loop).
7. Absence-based issues (no rate limit, no `max_tokens`) belong in the manual checklist; if ever automated, as a separate informational low-confidence family outside the `standard` profile.

## Remaining open items

- Structured YAML parsing for MCP configs, JSON agent configs (`.claude/settings.json`, `autoApprove`), wider filesystem-scope detection and connection-string secrets are not implemented.
- Dynamic evidence should record model id, temperature and prompt version.

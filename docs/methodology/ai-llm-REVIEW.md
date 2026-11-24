# Independent review: AI/LLM methodology, SEC-AI-001/002/003, ai-llm-security skill

Reviewer: independent (did not author the material). Date: 2026-11-20.
Scope reviewed: `docs/methodology/ai-llm.md`, `security_runner/adapters/ai_llm.py`, `security_runner/data/checks/ai-llm.json`, `skills/ai-llm-security/**`.

## Overall recommendation: APPROVE WITH CHANGES

The document is honest about its limits and the safety gates are sound. Required changes are mostly metadata and wording, plus one real detection bug (SQL f-string) that contradicts the "SQL" claim in the rule title. Preview automation is acceptable once required changes 1-8 are made. Rules should stay `experimental`.

## Sources checked (fetched 2026-11-20)

- OWASP Top 10 for LLM Applications 2025 list: https://genai.owasp.org/llm-top-10/
- CWE-1427 https://cwe.mitre.org/data/definitions/1427.html, CWE-1426 https://cwe.mitre.org/data/definitions/1426.html, CWE-732 .../732.html, CWE-250 .../250.html, CWE-494 .../494.html, CWE-770 .../770.html, CWE-829 .../829.html, CWE-639 .../639.html, CWE-778 .../778.html, CWE-532 .../532.html, CWE-502 .../502.html, CWE-94 .../94.html
- MCP security best practices https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices (latest 2026-07-28 at https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices), MCP tools spec https://modelcontextprotocol.io/specification/2025-11-25/server/tools

## Verdict per section

| Section | Verdict | Notes |
|---|---|---|
| Header / status / scope | accurate | Claims of "three static checks, two planned" match the code and JSON. |
| Global limitations | accurate | Honest. Add one line: rules skip any path under `tests/`, `testing/`, `__mocks__/` (see adversarial results). |
| 1 Trust boundaries | accurate | Table is reasonable. |
| 2 Prompt injection | accurate | CWE-1427 fit is good for direct injection (its description: product builds prompts from external data so the LLM cannot distinguish user input from system directives). CWE's own note says indirect injection / jailbreaking may have a different root cause, which the doc already hedges. Remove "reviewer to confirm". |
| 3 Output handling | needs change | OWASP LLM05 correct. Misses CWE-1426 (Improper Validation of Generative AI Output), which exists in CWE 4.15+ and cites OWASP insecure output handling as its source. It is the best primary mapping; 94/78/89/79 are downstream consequences. Coverage text overstates SQL detection (see bug A). |
| 4 Excessive agency | needs change | OWASP LLM06 correct. CWE-250 is a good fit: the CWE-250 page itself lists "Excessive Agency" as an alternate term from the OWASP 2025 list. CWE-94 on a rule that flags `allow_dangerous_code=True` is acceptable but secondary. Coverage line says "any approval-looking identifier suppresses"; code also suppresses on any sandbox-looking word (undocumented). |
| 5 MCP/agent config | needs change | See MCP findings below. CWE-732 is a poor fit. |
| 6 RAG | accurate | LLM08/LLM02/LLM04 titles exact. CWE-639/200 approximate, correctly labelled. |
| 7 Secrets/PII | accurate | CWE-532 title is "Insertion of Sensitive Information into Log File"; fine. |
| 8 Model supply chain | needs change | Technical claims need tightening (see below). |
| 9 Denial of wallet | accurate | OWASP LLM10 "Unbounded Consumption" exact. CWE-770 exists ("Allocation of Resources Without Limits or Throttling"); CWE-400 is the more conventional parent, mention both. |
| 10 Prompt leakage | accurate | LLM07 System Prompt Leakage exact. |
| 11 Logging | accurate | CWE-778 "Insufficient Logging" exists. |
| Coverage summary | accurate | |
| Open questions | needs change | Answers below. |
| Skill files | needs change | `catalog-checks.md` and `standards.md` carry the same statements; see change 9. |
| ai-llm.json | needs change | See metadata table. |

### OWASP IDs and titles

All ten IDs and titles in the doc, in `methodology.md`, `standards.md` and the JSON (`LLM01 Prompt Injection` ... `LLM10 Unbounded Consumption`) match the official 2025 list exactly. No corrections.

### CWE verification

| CWE | Exists / official title | Claimed use | Assessment |
|---|---|---|---|
| 1427 | Improper Neutralization of Input Used for LLM Prompting | prompt injection | Good fit. |
| 1426 | Improper Validation of Generative AI Output | not cited | Missing; add to SEC-AI-001 and topic 3. |
| 94 | Improper Control of Generation of Code | eval/exec of model output | Fits. |
| 78 | OS Command Injection | shell sinks | Fits. |
| 89 | SQL Injection | SQL sinks | Fits. |
| 79 | XSS | HTML sinks | Fits (no rule uses it). |
| 250 | Execution with Unnecessary Privileges | dangerous tools | Good; CWE page cross-refs OWASP Excessive Agency. |
| 732 | Incorrect Permission Assignment for Critical Resource | MCP filesystem root | Weak. CWE-732 is about permissions set on a resource (file modes, ACLs). A filesystem MCP server given `/` is over-broad privilege/scope, which is CWE-250 (or CWE-668 Exposure of Resource to Wrong Sphere). Replace. |
| 829 | Inclusion of Functionality from Untrusted Control Sphere | unpinned MCP packages, remote code | Fits; CWE-494 / CWE-1357 (Reliance on Insufficiently Trustworthy Component) are also reasonable for unpinned fetch. |
| 798 | Use of Hard-coded Credentials | inline tokens | Fits. |
| 494 | Download of Code Without Integrity Check | runtime weight download, `from_pretrained` without revision | Acceptable for downloaded code (remote code, unpinned). For pure weights in pickle format, CWE-502 is primary. "approximate" is the right label. |
| 502 | Deserialization of Untrusted Data | pickle | Fits. |
| 770 | Allocation of Resources Without Limits or Throttling | denial of wallet | Acceptable; add CWE-400. |
| 639 | Authorization Bypass Through User-Controlled Key | RAG tenant | Approximate; CWE-285/862 may fit better for missing tenant filter. |
| 532 / 778 | Sensitive info in log file / Insufficient Logging | | Fit. |

### MCP claims

- "Tool poisoning" and "rug-pull" are accurate as industry-documented attack classes but are NOT terms in the MCP specification. The spec does say clients MUST treat tool annotations as untrusted unless from trusted servers, and SHOULD keep a human in the loop for tool invocations (tools spec, 2025-11-25). Cite those, and attribute "tool poisoning" to its originators (Invariant Labs research, 2025) rather than to the spec.
- The MCP security best-practices page has a "Local MCP Server Compromise" section: clients must show the exact command being run and require explicit consent before launching local servers. Doc topic 5 should cite it; it directly motivates SEC-AI-002 and the pinning guidance.
- "remote (HTTP/SSE) servers": the standalone SSE transport was superseded by Streamable HTTP (spec 2025-03-26 onward). Change to "remote (Streamable HTTP, or legacy SSE) servers".
- Doc is silent on token passthrough, confused deputy and SSRF items in the spec; fine as scope, but add one sentence pointing to that page as normative guidance for server authors.

### Model artifact claims (topic 8)

- `pickle.load`/`joblib.load` on untrusted data: arbitrary code execution; correct (Python docs warn explicitly; CWE-502).
- `torch.load`: "without `weights_only=True`" is now version-dependent. PyTorch 2.6 changed the default to `weights_only=True`. Reword: "`torch.load` on untrusted files, or with `weights_only=False`, or on PyTorch < 2.6 without `weights_only=True`". Also add that `weights_only=True` is a mitigation, not a guarantee: CVE-2025-32434 was an RCE in `torch.load(weights_only=True)` fixed in 2.6.0. Require PyTorch >= 2.6.0 in the "secure behaviour" line. (PyTorch docs, torch.load notes; NVD CVE-2025-32434. I could not re-fetch these in this run; verify before publishing.)
- `trust_remote_code=True` executes Python from the model repo at load time; Hugging Face docs say to use it only for repos you trust and to pin `revision`. Claim is accurate. Note that pinning a commit hash is what makes this reviewable; a branch name is not a pin.
- safetensors: accurate that it is a non-executable tensor format. Do not imply that it makes the model trustworthy (poisoned weights/backdoors remain; LLM04). Add that Keras/other formats with executable layers (e.g. Keras Lambda layers outside safe_mode) and GGUF/ONNX parser bugs are separate risks; at minimum say "e.g." which the doc already does.
- `from_pretrained` without `revision`: correct as a weak signal.

## Safety / invention review

- No offensive instructions. Dynamic procedures use benign canary strings and require written scope, lab/staging only, synthetic data. `safety-and-states.md` bans credential attacks, DoS, production, exfiltration beyond one canary. Good.
- Doc says dynamic tests are "planned", unimplemented, and that the runner does not perform them. Consistent with JSON (`executor: none`, `maturity: unimplemented`).
- `dynamic-procedures.md` step 4 ("feed model-like outputs containing shell metacharacters to the sinks in a sandbox") should say explicitly that the sandbox has no secrets and no network; the methodology doc says this for code-execution features but the procedure does not. Add a sentence.
- Overstatements to fix: (a) `catalog-checks.md` says "precision-first"; the SQL false negative and the quoted-f-string miss show recall is weak and precision is unmeasured beyond synthetic fixtures. Say "heuristic, precision not established". (b) Doc header says "No AI/LLM checklist was supplied... original work"; fine, but standards references to "OWASP Top 10 for Agentic applications" in `standards.md` should name the actual document (OWASP "Agentic Security Initiative" / Top 10 for Agentic Applications) or be dropped; I could not verify the exact title from the sources fetched. (c) SKILL.md `compatibility: No network required` is fine.
- Skill says "Never run ... tests against production" and "mark blocked" without scope: correct and consistent.
- Minor: `safety-and-states.md` example scope has `"expires": "2026-12-31..."`, which is near today's date; harmless but use a clearly placeholder date.

## Metadata vs code behaviour

| Rule | Field | Finding |
|---|---|---|
| SEC-AI-001 | severity high / confidence medium | Severity is fine for a true positive. Confidence "medium" is generous given FNs below and FP on sanitised flows (`shlex.quote`, `int()`); recommend confidence `low` until field precision is published. |
| SEC-AI-001 | title "eval/exec/shell/SQL" | SQL detection misses the most common form, `execute(f"... '{out}'")` (placeholder wrapped in quotes) and `f'...'` single-quoted outer strings. Title/expected behaviour overclaim until fixed. |
| SEC-AI-001 | standards | Add CWE-1426. |
| SEC-AI-002 | title "unpinned packages, root filesystem exposure or inline tokens" | Matches code for npx/uvx/pnpm dlx. Does not cover docker `:latest`, `curl | sh`, git refs that are branches, plain-http remote URLs, credentials in URLs, Basic auth. Acceptable if title says "npx/uvx". `expected_secure_behavior` says "pinned to exact versions" but code accepts `^`, `~`, `>=`, and dist-tags like `@next` (see Q2): metadata contradicts behaviour. |
| SEC-AI-002 | "root filesystem" | Only exact `/`, `~`, `/home`, `/Users`, `/etc`, `/root`, `$HOME`, `C:\`. `/var`, `/usr`, a specific `~/.ssh` or another user's home are not flagged. CWE-732 should become CWE-250/CWE-668. |
| SEC-AI-003 | title "...without approval" | Flag patterns (`allow_dangerous_code=True` etc.) are reported regardless of approval; only ShellTool/REPL tools are approval/sandbox-gated. Title is slightly misleading; fine for catalog. Approval is file-wide and also matches `require_approval = False`. |
| SEC-AI-003 | `expected_secure_behavior` | Says "human approval and a sandbox"; the code suppresses on approval OR sandbox. Reword to "human approval or a sandbox" or tighten code. |
| SEC-AI-003 | file globs | JSON/shell/Markdown files are not scanned, so `--dangerously-skip-permissions` or `autoApprove` in `.json` agent configs (e.g. `.claude/settings.json`, `.cursor/mcp.json` `autoApprove`) is missed although doc topic 4 lists them as signals. |

## Adversarial test results

Method: temp dirs, `security_runner.regression.observations_for(rule, dir)`, run with `python3 -I`. Scripts in `/tmp/advrun/t.py`, `/tmp/advrun/t2.py` (outside repo). "Result" is the observed output; verdict is mine.

### SEC-AI-001

| # | Snippet | Result | Verdict |
|---|---|---|---|
| 1 | `cmd = resp...content; os.system(cmd)` | flagged | TP ok |
| 2 | `subprocess.run(cmd, shell=True)` | flagged | TP ok |
| 3 | `exec(compile(code,...))` | flagged | TP ok |
| 4 | `cur.execute(f"... n='{out}'")` | NOT flagged | **FN (bug A)**: regex `f["'][^"']*\{` fails if the f-string contains any quote before the placeholder; same for `f'... "{out}"'`. Only `f"... n={out}"` is caught. |
| 5 | `cur.execute("... %s", (out,))` parameterised | not flagged | correct |
| 6 | SQL concat `"..." + out` | flagged | TP ok |
| 7 | `safe = out.strip(); os.system(safe)` | NOT flagged | **FN**: any variable name matching `SAFE*/allow*/ALLOWED*` is treated as sanitised (`_ALLOW` applied to the RHS and the name). Name-based suppression. |
| 8 | `allowed = <llm output>; os.system(allowed)` | NOT flagged | **FN**, same cause. |
| 9 | `if out in ALLOWED: pass` then `os.system(out)` | NOT flagged | **FN**: a membership check with no enforcement (no `else`/`return`) untaints. Rare but real. |
| 10 | derived `sh = out.split(); subprocess.run(sh)` | flagged | TP ok |
| 11 | `for t in resp.choices: os.system(t.message.content)` | NOT flagged | FN (for-loop targets are not assignments; documented limitation class). |
| 12 | cross-function (`f` returns output, `g` evals) | NOT flagged | FN, documented. |
| 13 | `subprocess.run(['echo', msg])` list args | flagged | Likely FP (no shell; argument injection only). Low severity. |
| 14 | `d = json.loads(out); eval(d['x'])` | flagged | TP ok |
| 15 | `ast.literal_eval(out)` | not flagged | correct |
| 16 | `% out` SQL; JS `eval(code)` | flagged | TP ok |
| 17 | `innerHTML = code` | not flagged | FN, documented. |
| 18 | sink text inside string/comment | not flagged | correct |
| 19 | file under `tests/` | not flagged | by design |
| 20 | production code under a directory named `testing/` (`src/testing/a.py`) | NOT flagged | **FN**: `_TEST_PATH` skips any `testing/` dir; legitimate app packages with that name are silently skipped. |
| 21 | file with no LLM marker word | not flagged | by design (gate), but `c.generate(...)` alone does not mark a file; wrappers in other modules are invisible. |
| 22 | `out = shlex.quote(out); os.system('ls '+out)` | flagged | FP (sanitised). |
| 23 | `out = int(out); os.system('sleep %d' % out)` | flagged | FP (cast). |
| 24 | SQL via intermediate `q = f"...{out}"; execute(q)`; sqlalchemy `text(f"...")` | flagged | TP ok |

### SEC-AI-002

| # | Snippet | Result | Verdict |
|---|---|---|---|
| 25 | `pkg@^1.2`, `@~1.2`, `@>=1`, `@1` | not flagged | by design (Q2): wrong for supply-chain intent. |
| 26 | `pkg@latest`, `pkg@*` | flagged | ok |
| 27 | `pkg@next` (dist-tag) | NOT flagged | **FN**: any `@word` except `latest` counts as pinned; `@next`, `@beta`, `@canary` are mutable tags. |
| 28 | `npx pkg` without `-y` | not flagged | acceptable (npx prompts), but only when interactive; MCP clients often cannot answer. Low. |
| 29 | `npx -y -p pkg bin`, scoped pkgs, `pnpm dlx`, `uvx pkg>=1`, `uvx --from git+...`, `github:x/y#main` | flagged | ok |
| 30 | `docker run img:latest`; `bash -c "curl ...|sh"` | NOT flagged | FN (outside stated scope). |
| 31 | filesystem server with `/` | flagged | TP ok |
| 32 | filesystem server with `/home/alice`, `/var`, `/Users/bob/.ssh` | NOT flagged | FN: only exact roots; title says "root". |
| 33 | server named `fs` running `node server.js /` | NOT flagged | FN (name/arg heuristic). |
| 34 | env `GITHUB_TOKEN=ghp_...` | flagged | TP ok |
| 35 | env `${GITHUB_TOKEN}` | not flagged | correct |
| 36 | env `DB_URL=postgres://u:pw@h/db` | NOT flagged | FN: connection-string passwords. |
| 37 | env `API_KEY=abc123` (<8 chars) | NOT flagged | FN: length floor of 8. |
| 38 | `AUTH_MODE`, `MONKEY` env keys | not flagged | no FP (good). |
| 39 | URL `https://u:pw@h/mcp`; plain `http://` remote; `Authorization: Basic ...`; `--token=abcdefghijkl` arg | NOT flagged | FN x4. `_SECRET_VAL` only knows vendor prefixes and Bearer. |
| 40 | `.vscode/mcp.json` (`servers`), `.cursor/mcp.json` | flagged | ok |
| 41 | `.claude/settings.json`, `.claude.json` with mcpServers | NOT scanned | FN: glob requires "mcp" in filename. |
| 42 | `examples/mcp-example.json` | flagged | possible FP (docs/example file), not excluded. |
| 43 | YAML `args: ["-y","pkg"]` and block-list form | NOT flagged | **FN**: YAML is only matched via text regex `npx -y pkg` on one line; structured YAML configs are not parsed. Doc/catalog imply YAML support. |
| 44 | YAML literal `ghp_...` token | flagged | ok |

### SEC-AI-003

| # | Snippet | Result | Verdict |
|---|---|---|---|
| 45 | `PythonREPLTool()` / `BashTool()` / `new ShellTool()` / `PythonREPL().run` | flagged | TP ok |
| 46 | approval only in a comment | still flagged | correct (comments stripped) |
| 47 | `ShellTool()` plus unrelated `def x(): approve(y)` | NOT flagged | **FN** (Q3): any `approve(` suppresses. |
| 48 | `ShellTool()` plus `require_approval = False` | NOT flagged | **FN**: regex matches the identifier, not its value. Insecure config suppresses its own finding. |
| 49 | `ShellTool()` plus `sandbox_mode = 'none'` / `x = import sandbox_escape_tools` | NOT flagged | **FN**: any word starting `sandbox` suppresses; only `False/None/null` values un-suppress. |
| 50 | `sandbox_enabled = False` | flagged | ok |
| 51 | `allow_dangerous_code=True` with `require_approval=True` in file | flagged | ok (flags are unconditional) |
| 52 | `allow_dangerous_code=os.getenv(...)` | not flagged | FN, expected. |
| 53 | custom `run_shell` wrapped in `Tool(...)` | not flagged | FN, documented. |
| 54 | YAML `auto_approve: true` / `--dangerously-skip-permissions` | flagged | ok |
| 55 | YAML `auto_approve: yes` | NOT flagged | FN (YAML 1.1 boolean). |
| 56 | JSON agent config `autoApprove: true`, shell script with the flag | NOT scanned | FN (see metadata). |
| 57 | bare `PythonREPLTool` reference without call | not flagged | minor FN. |

Summary: 57 probes; core true positives work; 14 distinct false-negative classes, 3 false-positive classes. No crashes or exceptions on malformed input in the cases run.

## Open questions answered

1. **CWE mappings.** 1427 for prompt injection: accept. 250 for dangerous tools: accept (CWE-250 itself cites Excessive Agency). 732 for MCP filesystem scope: replace with CWE-250 (or CWE-668). 494: acceptable, labelled approximate; prefer 502 for pickle and 829 for remote code. 770: acceptable, add CWE-400. Add CWE-1426 for output handling.
2. **Should `^1.2` count as pinned?** No for MCP launchers. A launcher runs unattended with the user's privileges, and a range lets a compromised or rogue minor release execute without review. Treat as pinned only exact versions (`name@1.2.3`, `name==1.2.3`) or an immutable ref (commit SHA, integrity hash). Flag ranges, `latest`, `*`, dist-tags (`next`, `beta`) as "not exactly pinned", ideally as a distinct lower-severity detail ("version range") so users can tell them from fully unpinned. Update `expected_secure_behavior` consistency and `catalog-checks.md`.
3. **File-level approval/sandbox suppression in SEC-AI-003 too lenient?** Yes. Required: do not suppress on identifiers whose assigned value is false/none/`danger-full-access`; require the approval marker within the same function/call expression or tool-list statement (or at least within N lines), and require explicit sandbox config tokens (`sandbox=True`, `container`, `docker`, `network_policy`) rather than the bare word `sandbox`. Until then, downgrade to "shell tool present; approval/sandbox marker seen elsewhere in file" as a low-confidence observation instead of silent suppression, so the reviewer sees it.
4. **Should SEC-AI-004 (pickle / trust_remote_code) be added?** Yes, as experimental, after fixtures: it is a high-signal, low-noise pattern. Specs: flag `trust_remote_code=True` (any value other than literal False); `from_pretrained` with `trust_remote_code=True` and no `revision=` as higher; `pickle.load(s)`/`joblib.load`/`dill.load`/`cloudpickle.load` on non-literal paths (low confidence, many benign local uses); `torch.load` without `weights_only=True` (note PyTorch >= 2.6 default, so report as low confidence unless the pinned torch version is < 2.6 or `weights_only=False` is explicit). Map CWE-502 and CWE-829/494; OWASP LLM03. Safe forms: `weights_only=True` with torch >= 2.6.0, safetensors, pinned 40-hex `revision`. Needs fixtures before merge; severity medium, confidence low.
5. **(doc Q1)** answered above.
6. **(doc Q2)** answered above (no).
7. **(doc Q3)** answered above (yes, too lenient).
8. **(doc Q4) HTML/XSS and file-path/SSRF sinks in SEC-AI-001?** Keep SEC-AI-001 to execution sinks for now; add HTML sinks (`innerHTML`, `dangerouslySetInnerHTML`, `|safe`, `Markup(`) as a separate experimental rule (e.g. SEC-AI-005) because severity, CWE-79 mapping and FP profile differ. Leave file-path and SSRF to manual review (taint source/sink modelling too weak).
9. **(doc Q5)** answered in item 4 above; also acceptable safe forms: `trust_remote_code=False`, `revision=<40 hex>`, `use_safetensors=True`.
10. **(doc Q6) "approval must show actual arguments": requirement or recommendation?** Recommendation (SHOULD). MCP spec itself uses SHOULD for human-in-the-loop and confirmation prompts. Reword as "should".
11. **(doc Q7) Where do absence-based issues live?** Manual review checklist plus, if automated, a separate `confidence: low` "informational" rule family that is off by default in `standard` profile and only in `deep`. Do not mix with the high-severity rules.

## Required changes (numbered)

1. `docs/methodology/ai-llm.md` topic 3 Mapping: add `CWE-1426 (Improper Validation of Generative AI Output)` as the primary CWE; keep 94/78/89/79. Add `"CWE-1426"` to SEC-AI-001 `standards.cwe` in `security_runner/data/checks/ai-llm.json`.
2. Topic 5 Mapping and SEC-AI-002 `standards.cwe`: replace `CWE-732` with `CWE-250` (or CWE-668). Change doc text "CWE-732 (incorrect permission assignment; approximate fit...)" accordingly.
3. Fix bug A in `ai_llm.py::_sql_sink`: f-string alternative must allow quotes inside the literal (e.g. match `f["'].*\{\s*var\b` anchored to the string's own quote character), so `execute(f"... '{out}'")` and `execute(f'... "{out}"')` are flagged. Add fixtures. Until fixed, state in the doc (topic 3 Coverage) and in the JSON `title`/remediation that SQL detection is partial.
4. `ai_llm.py::_ALLOW`/`_ASSIGN` logic: stop treating a variable's own name (`safe`, `allowed`) as proof of sanitisation of its RHS; only treat explicit membership/lookup against an allow-list as validation, and only when it gates the sink (or document the limitation in topic 3, which currently says "can both over- and under-suppress" - acceptable only if the FN in probes 7-9 is listed).
5. SEC-AI-002 pinning: per Q2, do not count `^`, `~`, `>`, `<`, `*`, or dist-tags other than exact versions as pinned (or emit them as a separate lower-severity observation). Update topic 5 Coverage sentence ("Version ranges are currently treated as pinned"), `catalog-checks.md` ("Version ranges count as pinned"), and make `expected_secure_behavior` consistent with code. If behaviour is deliberately left unchanged for the preview, `expected_secure_behavior` and remediation text must say "exact version or range", not "exact versions".
6. SEC-AI-003: (a) do not suppress when the matched approval/sandbox identifier is assigned `False/None/'none'/'off'` or `danger-full-access`; (b) update `expected_secure_behavior` from "approval and a sandbox" to match code ("approval or sandbox"), or change the code; (c) document in topic 4 Coverage that any sandbox-looking identifier also suppresses, not only approval identifiers; (d) confidence in JSON `low` for the REPL/shell-tool sub-rule.
7. SEC-AI-001 JSON `confidence`: set to `low` (or keep medium only if the field sample in `docs/RULE-ACCURACY-FIELD-ai-llm.md` supports it; I could not find evidence in the reviewed files). Fix `catalog-checks.md` "precision-first" wording.
8. Topic 8 text: replace "`torch.load` without `weights_only=True`" with the version-aware wording above; add the CVE-2025-32434 caveat and "PyTorch >= 2.6.0"; state that safetensors removes code execution on load but not poisoning. Topic 5: replace "(HTTP/SSE)" with "(Streamable HTTP, or legacy SSE)"; attribute "tool poisoning/rug-pull" to published research, not the MCP spec; add reference to the MCP Security Best Practices page and the tools-spec statement that tool annotations are untrusted.
9. Skill docs: in `skills/ai-llm-security/references/standards.md` add CWE-1426, replace CWE-732 mention, and either name the agentic document precisely or delete the "OWASP Top 10 for Agentic applications" line; in `catalog-checks.md` fix the two sentences from changes 5 and 7 and note that rules skip any `tests/`, `testing/`, `__mocks__/` directory; in `dynamic-procedures.md` step 4 add "sandbox with no secrets and no network".
10. Doc "Open questions" section: either record the answers above as resolved decisions or leave open and mark status; Q6 should be decided as SHOULD.
11. Document known FNs found here in the "What the static rules do and do not see" list: structured YAML MCP configs are not parsed (only one-line `npx -y pkg` text), JSON agent configs/`.claude/settings.json` not scanned, `testing/` directories skipped, filesystem scope covers only exact roots, secret detection covers vendor prefixes/Bearer only.

## Recommended optional changes

- Parse YAML MCP files with `yaml.safe_load` (if PyYAML is acceptable as a dependency) instead of regexes.
- Add `.claude.json`, `.claude/settings*.json`, `.cursor/**/*.json`, `.vscode/mcp.json` to SEC-AI-002/003 globs; add `autoApprove` and `dangerouslySkipPermissions` JSON key detection to SEC-AI-003.
- Widen filesystem-scope detection to any path under `/etc`, `/var`, `/usr`, `~/.ssh`, `~/.aws`, home directories of any user, and apply the check to all servers whose args contain a root, not only those named "filesystem".
- Add connection-string passwords, `Basic` auth, `user:pass@` URLs, and generic `--token=`/`--api-key=` args to secret detection; lower the 8-char floor for keys that match strongly named env keys.
- Skip `examples/`, `docs/`, `fixtures/` for SEC-AI-002 or lower their confidence.
- Treat `shlex.quote(...)`, `int(...)`, `float(...)` and `json.loads` + schema validation as sanitisers (or document as FP).
- Flag `docker run img` without digest/tag and plain `http://` remote MCP URLs as separate low-severity observations.
- Fix `_TEST_PATH` so `testing/` only matches when it is clearly test code (e.g. `tests/` and `__tests__/` only).
- Add CWE-400 alongside CWE-770 in topic 9; consider CWE-285/862 for tenant-filter absence in topic 6.
- Replace the example scope expiry date in `safety-and-states.md` with an obviously placeholder value.
- Add a short "model/prompt versions" note: dynamic evidence must record model id, temperature and prompt version (already implied in Global limitations 3).

## Final recommendation: APPROVE WITH CHANGES

Reasons: factual standards content (OWASP IDs/titles, most CWEs, MCP claims, safety gates) is accurate; honesty about limits is strong; metadata has several mismatches with code (pinning semantics, approval-or-sandbox, SQL coverage, confidence) and one concrete SQL detection bug; CWE-732 and the missing CWE-1426 are mapping errors; the torch.load statement is outdated. None of this is unsafe. Preview automation may proceed with rules marked experimental once changes 1-8 are done; 9-11 should land in the same pull request but are not blockers.


## Resolution (author response, applied after review)

Required changes:

1. CWE-1426 added to topic 3 mapping (as primary) and to SEC-AI-001 `standards.cwe` in `ai-llm.json`. Done.
2. CWE-732 replaced by CWE-250 in topic 5 and SEC-AI-002 metadata; `skills/.../standards.md` explains why 732 is not used. Done.
3. `_sql_sink` fixed: f-strings with quoted placeholders (`'{out}'`, `"{out}"`, either outer quote) are flagged. Accuracy cases `ai001-pos-sql-quoted-fstring-dq/-sq`; SQL coverage still described as partial in the SEC-AI-001 title and doc.
4. Fixed rather than documented: variable names (`safe`, `allowed`) no longer sanitise. Only enforced membership tests or direct lookups against allow-list-named containers (never the tainted variable itself) and cast/quote wrappers clear taint. A bare `if out in ALLOWED: pass` followed by the sink is flagged. Cases `ai001-pos-safe-named-variable`, `ai001-pos-unenforced-membership`, `ai001-neg-positive-membership-guard`, `ai001-neg-js-includes-guard`.
5. SEC-AI-002: ranges (`^ ~ > < * x`), major-only versions and dist-tags (`latest`, `next`, `beta`) are reported with a distinct detail ("not pinned to an exact version (range or dist-tag)"); exact versions, 40-hex SHAs and integrity hashes are pinned. Also fixed `uvx --python X pkg` argument parsing and git/github sources. `expected_secure_behavior`, remediation, title, doc and `catalog-checks.md` updated. Cases `ai002-pos-caret-range`, `-tilde-and-gte-range`, `-dist-tag-next`, `ai002-neg-git-sha-pin`, `-exact-prerelease`.
6. SEC-AI-003: approval/sandbox markers are scoped to the enclosing function (class for methods; module-level code if none); markers assigned off values (`require_approval = False`, `sandbox_mode = 'none'`) and import lines do not count; a bare word `sandbox` no longer counts (explicit tokens: `*Sandbox*` identifiers, `sandbox=True`, `docker`, `container_auto`, `network_policy`, ...). Check confidence set to `low` (Observation has no per-observation confidence, so the whole check is low and the shell/REPL detail says "low confidence"). `expected_secure_behavior` now says "approval or sandbox". Cases `ai003-pos-approval-other-function`, `-require-approval-false`, `-sandbox-mode-none`, `-sandbox-import-word`, `ai003-neg-approval-same-function`, `-sandbox-same-function`. Also `auto_approve: yes` and `autoApprove` now match.
7. SEC-AI-001 confidence `low`; "precision-first" wording replaced by "heuristic, precision not established". `shlex.quote()`, `int()`, `float()`, `re.escape`, `parseInt`, `Number` flows treated as sanitised (cases `ai001-neg-shlex-quote`, `ai001-neg-int-cast`).
8. Topic 8/5 wording applied. CVE-2025-32434 was fetched from the NVD API on 2026-11-20 and confirmed (RCE in `torch.load` with `weights_only=True`, versions 2.5.1 and prior, patched in 2.6.0), so it is cited. torch.load text is version aware; safetensors removes code execution on load, not poisoning; "Streamable HTTP, or legacy SSE"; tool poisoning/rug pull attributed to published research (Invariant Labs, 2025) not the spec; spec statements (tool annotations untrusted; SHOULD human in the loop) and the Security Best Practices page cited. These MCP spec statements are taken from the review and were not independently re-fetched by the author.
9. Skill docs: `standards.md` (CWE-1426 added, 732 dropped, agentic OWASP line replaced by an explicit not-cited note), `catalog-checks.md` (test directories skipped, ranges not pinned, no "precision-first"), `dynamic-procedures.md` step 4 (no secrets, no network). Also the example scope expiry in `safety-and-states.md` is now a placeholder.
10. Open questions recorded as resolved decisions in the methodology doc; Q6 decided as SHOULD.
11. Known false negatives added to the doc (YAML not parsed structurally, `.claude/settings.json` and JSON agent configs not scanned, exact-roots filesystem scope, secret detection limits, SQL/for-loop/cross-function FNs).

Also done: `_TEST_PATH` no longer skips `testing/` directories (production packages with that name are scanned; case-by-test `test_testing_directory_is_not_skipped`). Optional SEC-AI-004 (trust_remote_code, pickle-family and unsafe torch.load) added as experimental, confidence low, with fixtures (`fixtures/ai-llm-app`) and 9 accuracy cases. Doc status set to "REVIEWED WITH CHANGES - experimental".

Declined / not done (optional items): structured YAML parsing, JSON agent config scanning (`.claude/settings.json`, `autoApprove` keys), wider filesystem scope, connection-string/Basic-auth secrets, skipping `examples/` for SEC-AI-002, separate HTML-sink rule, docker/plain-http observations. Reason: optional, each needs its own fixtures and accuracy evidence; listed under "Remaining open items" in the methodology doc.

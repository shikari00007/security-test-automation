# Security & Test Automation Skills

> **Developer Preview (0.3.0rc1) - not production-ready.** Static results are *candidates*, not confirmed vulnerabilities. Dynamic testing is **unimplemented**. Expect false positives and false negatives. See [docs/RELEASE-GATES.md](docs/RELEASE-GATES.md) and [docs/RULE-ACCURACY.md](docs/RULE-ACCURACY.md).

Portable security skills for coding agents (Claude Code, Codex, Cursor, Gemini CLI, VS Code / GitHub Copilot, and other Agent Skills-compatible agents), plus an optional offline-by-default Python runner that executes static checks, records verifiable evidence, generates regression tests and writes JSON / SARIF / JUnit XML / Markdown reports.

## Install the skills

```bash
npx skills add shikari00007/security-test-automation
npx skills add shikari00007/security-test-automation --skill security-do   # one skill
```
This installs 16 independent skills (`skills/*/SKILL.md`). The installer copies skills only; it does not install the runner. *(The one-line command works only once the repository is published; see release status below.)*

## Install the runner (optional)

```bash
pip install .            # Python >= 3.10, no runtime dependencies
security-skills audit ./application --type auto --profile standard --report sarif,json,markdown
```
Commands: `detect`, `plan`, `audit`, `verify`, `confirm`, `coverage`, `rerun`, `regression generate|verify`, `catalog checks`, `skills validate`.
Exit codes: `0` ok, `1` gating findings, `2` usage/policy error, `3` integrity failure. By default the gate fails on reproduced **high-confidence candidates** at or above `--fail-on high`; `--gate confirmed` gates only independently validated findings.

## Domains
Web, API, Android, iOS, Desktop / Thick Client, Supply Chain / DevSecOps (always eligible), and conditional Cloud & Kubernetes and AI / LLM. Wireless, IoT/embedded and standalone Active Directory testing are out of scope. Enterprise authentication (LDAP, Kerberos, SSO, OAuth/OIDC) is covered where relevant to an application.

## What is and is not implemented

| Area | Implemented (Developer Preview) | Not implemented / experimental |
|---|---|---|
| Skills | 16 spec-valid skills, progressive-disclosure references, manual fallback without the CLI | Not yet exercised inside live agent sessions |
| Static rules | 48 built-in rules across 8 domains with secure/vulnerable fixtures and an adversarial accuracy corpus | AI/LLM rules (4) are **experimental**; precision on real code is only spot-checked |
| Dynamic testing | Policy gate and scope-file validation | **Unimplemented**: 15 dynamic/hybrid/manual checks are listed as blocked, never executed |
| External tools | Catalogued (osv-scanner) | **Unimplemented**: reported as blocked |
| Regression tests | pytest (verified red on vulnerable / green on fixed tree) | Playwright and Schemathesis outputs are **experimental skeletons, not executed**; no JUnit/XCTest/Espresso generators |
| Reports | JSON, SARIF 2.1.0, JUnit XML, Markdown | HTML/PDF |

## Accuracy - read before relying on results

Measured by triaging findings on real public code (details and per-finding verdicts in `docs/RULE-ACCURACY-FIELD-*.md`):

| Rules | Sample | Strict precision | Notes |
|---|---|---|---|
| Web / API / Supply chain (23 rules) | 282 sampled findings | **51%** (85% if correct patterns in benign or intentional contexts are counted) | Worst: SC-001 4%, WEB-002 4%, WEB-005 8%, SC-006 20%. These are `low` confidence and excluded from Quick and the default CI gate. Seven rules had no field findings at all, so their accuracy rests on the synthetic corpus only. |
| Android / iOS / Desktop / Cloud-K8s (21 rules) | 184 triaged hits | 88% before fixes, 100% after | The post-fix figure was tuned on the same repos, which lean toward intentionally vulnerable apps and examples, so it is optimistic. Several rules had no real positive sample. |
| AI / LLM (4 rules, **experimental**) | 5 public repos | 0 findings (21 false positives before fixes) | No true positive was ever observed, so recall is unmeasured. Methodology was independently reviewed; the post-review code was not. |

"True positive" means the pattern is really present, not that it is exploitable. The synthetic accuracy corpus (524 cases) reports 0 false positives / 0 false negatives **by construction** - rules were tuned until every case passed - so it is a regression guard, not an accuracy estimate. Static analysis here is line/pattern based with no data-flow analysis; expect both false positives and false negatives.

**Default CI gate:** `security-skills audit` exits 1 only for confirmed findings and *high-confidence* reproduced candidates at or above `--fail-on` (default `high`). Low- and medium-confidence candidates never gate unless you pass `--strict`.

**Experimental / unimplemented:** the 4 AI/LLM rules are experimental; the 15 dynamic, hybrid and manual checks and the osv-scanner adapter are unimplemented (reported as blocked, never executed); Playwright and Schemathesis regression outputs are unexecuted skeletons.

## Result states (never conflated)
`status`: planned / not_applicable / blocked / deferred / executed. `outcome` (executed only): pass / fail / inconclusive. Finding status: **candidate** (static match, even after automatic re-execution) -> **needs_validation** / **rejected**, or **confirmed**, which requires a recorded independent validation (`security-skills confirm`: validator, method, violated boundary, evidence-artifact hash). A passed check covers only that check's pattern. See [docs/VERIFICATION.md](docs/VERIFICATION.md).

## Safety model
Offline and read-only by default; the runner has no network code; symlinks are never followed out of the target; output inside the target tree is refused; subprocesses are allow-listed with scrubbed environment, timeouts, output caps and resource limits; secrets are redacted from evidence; dynamic modes need a valid scope file (lab/staging only, explicit targets, authorization, isolation, unexpired; production is always refused). Skills are guidance, not a sandbox. Hash-chained manifests are tamper-*evident*; add `--hmac-key-env` for a keyed signature. See [SECURITY.md](SECURITY.md).

## Catalog
Only *reviewed* checks (`security_runner/data/checks/`) can execute. A larger normalized catalog exists as an internal, unreviewed maintainer artifact and is not published. See [docs/CATALOG.md](docs/CATALOG.md).

## Layout
`skills/` agent skills | `security_runner/` CLI, engine, adapters, reviewed check data | `fixtures/` secure/vulnerable pairs and accuracy corpus | `tests/` | `scripts/` release build and gates | `docs/`.

## License and attribution
Apache-2.0 (see [LICENSE](LICENSE), [NOTICE](NOTICE)). Methodology inspired by cloudflare/security-audit-skill, petrkindlmann/qa-skills and SnailSploit/Claude-Red (all MIT; no code or text copied); details and pinned revisions in [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md).

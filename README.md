# Security & Test Automation Skills for AI Agents

**Application security skills for the coding agent you already use - plus an optional offline-first CLI that finds candidate issues, checks the evidence, and turns confirmed problems into regression tests.**

```bash
npx skills add shikari00007/security-test-automation
```

[![Status: Developer Preview](https://img.shields.io/badge/status-Developer%20Preview-orange.svg)](#honest-limitations-and-accuracy)
[![Agent Skills](https://img.shields.io/badge/Agent%20Skills-16-blue.svg)](#skills-catalog)
[![Domains](https://img.shields.io/badge/security%20domains-8-informational.svg)](#security-domains)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Agent Skills Standard](https://img.shields.io/badge/Agent_Skills-Standard-purple.svg)](https://agentskills.io/specification)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](pyproject.toml)
[![CI](https://github.com/shikari00007/security-test-automation/actions/workflows/validate.yml/badge.svg)](https://github.com/shikari00007/security-test-automation/actions/workflows/validate.yml)

Works with Claude Code, Codex, Cursor, Gemini CLI, VS Code / GitHub Copilot and other agents that support the [Agent Skills Standard](https://agentskills.io/specification). The skills work on their own; the CLI is optional.

> **Developer Preview - not production-ready.** A static rule match is a *candidate*, not a confirmed vulnerability. Dynamic testing is not implemented. On real code, the evaluated Web/API/Supply-chain rules had **51% strict precision**. Read [Honest limitations and accuracy](#honest-limitations-and-accuracy) before relying on any result.

## Contents
[Quick start](#quick-start) - [Example prompts](#example-prompts) - [Supported agents](#supported-ai-coding-agents) - [Skills catalog](#skills-catalog) - [Security domains](#security-domains) - [Profiles](#audit-profiles) - [CLI runner](#optional-cli-runner) - [Developer workflow](#developer-security-workflow) - [Regression testing](#security-automation-and-regression-testing) - [Limitations](#honest-limitations-and-accuracy) - [Contributing](#contributing-and-community) - [License](#license-and-acknowledgments)

## Quick start

### 1. Install the skills

```bash
npx skills add shikari00007/security-test-automation
```

The installer asks which agents to target. To skip the prompt, add `-y`; to choose agents explicitly, add `-a`:

```bash
npx skills add shikari00007/security-test-automation -a claude-code -a codex -y
npx skills add shikari00007/security-test-automation --skill api-security-testing   # one skill only
```

Skills land in your project's agent directory (`.claude/skills/` for Claude Code, `.agents/skills/` for the shared layout used by other agents). The installer copies **skills only**; it does not install the CLI.

### 2. Ask your agent

Open the project in your agent and ask for a security review (see [example prompts](#example-prompts)). The agent picks up the relevant skills; you can also name one directly, for example "use `security-start`".

### 3. Optional: add the CLI for deterministic, offline checks

```bash
python -m pip install "git+https://github.com/shikari00007/security-test-automation.git"
security-skills audit ./my-app --type auto --profile standard --report sarif,json,markdown --output-dir ./security-artifacts
```

The CLI is installed from GitHub (it is not on PyPI). Python 3.10 or newer; no runtime dependencies. The output directory must be outside the project being audited.

## Example prompts

> Review this repository with `security-start`. Detect the stack, recommend a Quick, Standard or Deep profile, and list the applicable checks before doing anything.

> Audit this application using the Standard security profile, identify applicable vulnerabilities, verify the findings independently and propose security regression tests.

> Use `api-security-testing` to review authentication and authorization in this backend. Treat static matches as candidates and show the evidence for each.

> This Dockerfile and these Kubernetes manifests are in scope. Use `cloud-kubernetes-security` and tell me which checks were not run and why.

> Use `security-finding-validation` to try to disprove finding FIND-1234 using only the evidence packet.

> Write a security regression test for this verified bug. Do not change application code until I approve.

## Supported AI coding agents

| Agent | Install | Status in this project |
|---|---|---|
| Claude Code | `npx skills add` -> `.claude/skills/` | Install verified; skill discovery verified in a live session |
| Codex | `npx skills add -a codex` -> `.agents/skills/` | Install layout verified; live loading not tested |
| Cursor | `npx skills add -a cursor` -> `.agents/skills/` | Install layout verified; live loading not tested |
| Gemini CLI | `npx skills add -a gemini-cli` -> `.agents/skills/` | Install layout verified; live loading not tested |
| VS Code / GitHub Copilot | `npx skills add -a github-copilot` -> `.agents/skills/` | Install layout verified; live loading not tested |
| Other Agent Skills-compatible agents | copy `skills/<name>/` into the agent's skills directory | Standard-compliant (validated with `security-skills skills validate`); not tested per agent |

"Install verified" means the installer produced all 16 spec-valid skills, byte-identical to this repository. Activation behavior depends on the host agent.

## Skills catalog

Sixteen independently installable skills. Each is a `SKILL.md` with on-demand `references/` and works without the CLI. See [`skills/README.md`](skills/README.md).

| Category | Skill | Use it for |
|---|---|---|
| Foundation | [`security-start`](skills/security-start) | Detect the stack and propose a scoped starting plan |
| Foundation | [`security-project-context`](skills/security-project-context) | Capture application context, assets and constraints |
| Foundation | [`security-do`](skills/security-do) | Single entry point: turn a plain request into a configured assessment |
| Planning | [`security-test-strategy`](skills/security-test-strategy) | Risk-based Quick / Standard / Deep strategy |
| Planning | [`security-coverage-analysis`](skills/security-coverage-analysis) | Record what was tested, blocked and not tested |
| Domain | [`web-security-testing`](skills/web-security-testing) | Web application review |
| Domain | [`api-security-testing`](skills/api-security-testing) | REST / GraphQL / gRPC API review |
| Domain | [`android-security-testing`](skills/android-security-testing) | Android app review |
| Domain | [`ios-security-testing`](skills/ios-security-testing) | iOS app review |
| Domain | [`desktop-security-testing`](skills/desktop-security-testing) | Desktop and thick-client review |
| Domain | [`supply-chain-security`](skills/supply-chain-security) | Dependencies, CI/CD, secrets, build integrity |
| Domain | [`cloud-kubernetes-security`](skills/cloud-kubernetes-security) | Containers, IaC, RBAC (conditional) |
| Domain | [`ai-llm-security`](skills/ai-llm-security) | LLM apps, agents, RAG, MCP (conditional, experimental) |
| Assurance | [`security-finding-validation`](skills/security-finding-validation) | Independent, adversarial validation of a candidate |
| Assurance | [`security-regression-generation`](skills/security-regression-generation) | Propose regression tests for validated findings |
| Assurance | [`security-reporting`](skills/security-reporting) | Reports with evidence, coverage and limits |

## Security domains

| Domain | Activated when | Executable static rules | Planned / manual checks (not executed) |
|---|---|---|---|
| Web application | Web framework or UI detected | 10 | 3 |
| API | OpenAPI / GraphQL / server framework detected | 6 | 2 |
| Android | Android project or manifest | 6 | 2 |
| iOS | Xcode project, `Info.plist`, entitlements | 4 | 2 |
| Desktop / thick client | Electron, .NET, Java or native desktop | 5 | 2 |
| Supply chain / DevSecOps | Every project (each check decides applicability) | 7 | 1 (external tool adapter) |
| Cloud & Kubernetes | Dockerfile, Helm, Terraform or manifests | 6 | 1 |
| AI / LLM | LLM SDKs, agents, MCP or RAG detected | 4 (experimental) | 2 |

48 executable static rules and 15 planned checks in total. "Planned" means catalogued with its expected secure behavior but **not automated**; the runner reports them as `blocked`, never as passed. Wireless, IoT/embedded and standalone Active Directory testing are out of scope; application-facing enterprise authentication (LDAP, Kerberos, SSO, OAuth/OIDC) is in scope where relevant.

## Audit profiles

| Profile | Best for | What it selects |
|---|---|---|
| **Quick** | While coding, pull requests | Only higher-confidence static checks that apply to the project |
| **Standard** | Before merge | All applicable static checks. Dynamic and manual checks are outside this profile (reported as deferred); the external-tool check is reported as blocked |
| **Deep** | Before release | Standard plus every catalogued dynamic, hybrid and manual check shown as blocked until you authorize it |

Profiles choose breadth; they do not guarantee that a vulnerability class has been fully tested, and **no profile performs active exploitation**.

## Optional CLI runner

```bash
security-skills detect ./app                          # what is this project? which domains apply?
security-skills plan ./app --profile standard         # what would run, what is not applicable or blocked
security-skills audit ./app --profile standard --output-dir ./security-artifacts
security-skills verify ./security-artifacts/run.json --target ./app    # re-check evidence integrity
security-skills coverage ./security-artifacts/run.json
security-skills rerun ./security-artifacts/run.json   # re-audit and diff: fixed / new / persisting
```

Example output (real run on the Android fixture in this repository):

```text
audit run-20261124T230809Z-fb8693 profile=standard domains=android,supply-chain
  executed 7/8 applicable | passed 1 failed 6 | blocked/untested 1 | not applicable 53
  confirmed vulnerabilities 0 | reproduced candidates 6 | needs validation 4 | rejected 0
  note: static matches are CANDIDATES; only `security-skills confirm` (independent validation) makes a finding confirmed
```

Reports: `results.json`, `results.sarif` (SARIF 2.1.0), `junit.xml`, `REPORT.md`, plus the sealed `run.json`. Exit codes: `0` ok, `1` gating findings, `2` usage or policy error, `3` integrity failure.

The runner is offline and read-only: it has no network code, never follows symlinks out of the project, refuses to write inside the audited tree, runs helper processes with allow-lists and resource limits, and redacts secrets in evidence. See [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## Developer security workflow

| Stage | What to do | Tooling |
|---|---|---|
| While coding | Ask your agent to run `security-start`, or run a Quick audit | Skills, or `--profile quick` |
| Pull request | Run Quick in CI and upload SARIF to code scanning | CLI + `upload-sarif` |
| Review | Treat each result as a candidate; try to disprove it from the evidence | `security-finding-validation` |
| Confirm | Record an independent validation for real issues | `security-skills confirm` |
| Lock in | Generate a regression test for the fixed behavior | `security-skills regression generate` |
| Before release | Standard or Deep audit; read the untested list, not just the findings | `security-reporting`, `REPORT.md` |

A GitHub Actions example (adapted from this repository's own [CI](.github/workflows/validate.yml)):

```yaml
- uses: actions/setup-python@v5
  with: {python-version: "3.12"}
- run: python -m pip install "git+https://github.com/shikari00007/security-test-automation.git"
- run: security-skills audit . --profile quick --report sarif,json --output-dir "$RUNNER_TEMP/security"
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: {sarif_file: "${{ runner.temp }}/security/results.sarif"}
```

By default `audit` fails the job (exit 1) only for confirmed findings and **high-confidence** candidates at or above `--fail-on high`. Low- and medium-confidence candidates never fail the build unless you pass `--strict`; use `--gate confirmed` to fail only on independently validated findings.

## Security automation and regression testing

Finding states are never conflated: a check is `planned`, `not_applicable`, `blocked`, `deferred` or `executed`; an executed check has the outcome `pass`, `fail` or `inconclusive`; a finding is a `candidate`, `needs_validation`, `rejected` or `confirmed`. `confirmed` requires a recorded independent validation:

```bash
security-skills confirm ./security-artifacts/run.json --finding FIND-XXXXXXXXXX \
  --validator "your name" --method manual-review \
  --boundary "Describe the security boundary that was actually violated" \
  --evidence-file ./notes/poc.txt
```

Evidence is checked, not trusted: a non-empty evidence string proves nothing. `verify` re-hashes every examined file, re-checks each cited line, validates the hash chain and rejects fabricated or inconsistent results.

Regression tests assert the *secure* behavior and are only proposed - your source code is never modified:

```bash
security-skills regression generate --results ./security-artifacts/run.json --finding FIND-XXXXXXXXXX \
  --accept-candidate --output-dir ./security-regression     # candidate-derived tests are labelled as such
security-skills regression verify --test ./security-regression/test_find_xxxxxxxxxx.py \
  --vulnerable ./app --fixed ./app-after-fix                # must fail on vulnerable, pass on fixed
```

The pytest generator is verified red/green against the local secure and vulnerable fixtures. Playwright and Schemathesis outputs are **unexecuted skeletons**; JUnit, XCTest and Espresso generators do not exist yet.

## Honest limitations and accuracy

| Area | Status |
|---|---|
| Static rule precision, Web / API / Supply chain (23 rules), earlier field triage before the rule rework | **51% strict precision** (85% if correct patterns in benign or intentional contexts are counted) in a triage of 282 real findings; weakest rules: SC-001 4%, WEB-002 4%, WEB-005 8%, SC-006 20%. These are low confidence and excluded from Quick and from the default CI gate. Seven rules produced no field findings, so their accuracy rests on a synthetic corpus only |
| Reworked rules (SC-001, SC-006, WEB-002, WEB-005, WEB-006), two fresh hold-outs | Independent blind labelling on repositories the authors never saw: **no sampled finding was shown exploitable (strict precision 0%)**. Pattern precision (a genuine pattern, including benign or intentional context) rose from 66% to 82% (hold-out 2) and from 81% to 91% (hold-out 3); recall of known-vulnerable locations rose from 29% to 42% and from 34% to 45%. SC-006 improved most (precision 32% to 76% on hold-out 3); SEC-WEB-002 precision did not improve; **Python recall is still low (8 of 28 on hold-out 3) and Java is unchanged (6 of 14)**; some samples are small. On the OWASP Benchmark (hold-out 4) recall rose from 19% to 33% but the share of designed-benign cases wrongly flagged also rose, from 15% to 27%. The earlier and these measurements use different samples and labelling and are not comparable. See [docs/ACCURACY-HOLDOUT.md](docs/ACCURACY-HOLDOUT.md) |
| Mobile / Desktop / Cloud rules (21 rules) | 88% before fixes, 100% after - but tuned on the same sample, which leans toward intentionally vulnerable apps, so treat it as optimistic |
| AI / LLM rules (4) | **Experimental.** Zero findings on five public repositories; no true positive observed, so recall is unmeasured. The methodology was independently reviewed; the post-review code was not |
| Dynamic testing, external tool adapters | **Not implemented.** 15 checks are catalogued but never executed |
| Regression generators | pytest verified; Playwright / Schemathesis are skeletons |
| Static analysis | Mostly line and pattern based with limited same-function dataflow; PHP and Java sink detection is new and has no benign real-world corpus behind it; expect false positives **and** false negatives |
| A passed check | Covers only that check's pattern, not an application or a vulnerability class |
| Live agent testing | Skill discovery was verified in Claude Code only |

"True positive" here means the pattern is present, not that it is exploitable. The accuracy corpus (524 hand-written cases) reports 0 false positives and 0 false negatives *by construction* because rules were tuned until it passed; it is a regression guard, not an accuracy estimate. Details: [`docs/RULE-ACCURACY.md`](docs/RULE-ACCURACY.md), [web/API/supply chain triage](docs/RULE-ACCURACY-FIELD-web-api-sc.md), [mobile/desktop/cloud triage](docs/RULE-ACCURACY-FIELD-mobile-desktop-cloud.md), [AI/LLM triage](docs/RULE-ACCURACY-FIELD-ai-llm.md), [AI/LLM methodology](docs/methodology/ai-llm.md).

Use this only on software you own or are authorized to assess. Never run it against production systems or third parties without written scope.

## Project layout

```text
skills/            The 16 installable Agent Skills (SKILL.md + references/)
security_runner/   Offline-first CLI, engine, rules and reviewed check data
fixtures/          Secure and vulnerable sample projects, plus the accuracy corpus
tests/             Automated tests for the framework itself
scripts/           Release, integrity and consistency checks
docs/              Verification model, accuracy results, methodology, release gates
```

## Contributing and community

Contributions are welcome from developers, QA engineers, security researchers and technical writers: new skills, safer and more precise rules, fixtures, accuracy measurements, and documentation.

- Start with [CONTRIBUTING.md](CONTRIBUTING.md) (setup, adding a skill, adding a check, tests, pull-request expectations).
- Questions, bugs and ideas: [GitHub Issues](https://github.com/shikari00007/security-test-automation/issues).
- Found a vulnerability in this framework? Report it privately as described in [SECURITY.md](SECURITY.md); do not open a public issue.
- Release history: [CHANGELOG.md](CHANGELOG.md).

## License and acknowledgments

Released under the **[MIT License](LICENSE)** - Copyright (c) 2026 shikari00007. See [NOTICE](NOTICE).

The earlier Developer Preview release [`v0.3.0rc1`](https://github.com/shikari00007/security-test-automation/releases/tag/v0.3.0rc1) was published under Apache-2.0 and keeps those terms.

Methodology was informed by [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill), [petrkindlmann/qa-skills](https://github.com/petrkindlmann/qa-skills) and [SnailSploit/Claude-Red](https://github.com/SnailSploit/Claude-Red) (all MIT; no code or text copied; pinned revisions in [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md)). Third-party security checklists used privately during development are **not** included in this repository.

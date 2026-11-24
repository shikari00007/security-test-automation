# Contributing to Security & Test Automation Skills

Thank you for helping make application-security testing more useful during development. Contributions are welcome from developers, QA engineers, application-security engineers, researchers and technical writers - you do not need to be a security specialist to improve documentation, fixtures, or skill wording.

**Contents:** [Before you start](#before-you-start) - [Development setup](#development-setup) - [Testing your changes](#testing-your-changes) - [Creating an Agent Skill](#creating-an-agent-skill) - [Contributing a security check](#contributing-a-security-check) - [Evidence and verification requirements](#evidence-and-finding-verification-requirements) - [Coding and documentation standards](#coding-and-documentation-standards) - [Backward compatibility](#maintaining-backward-compatibility) - [Safety rules](#safety-restrictions-on-security-testing) - [Pull requests](#pull-request-expectations) - [Reporting vulnerabilities](#reporting-security-vulnerabilities) - [Licensing](#licensing-and-attribution)

## Before you start

- Search [existing issues](https://github.com/shikari00007/security-test-automation/issues) and pull requests first.
- For anything larger than a small fix (a new skill, a new check, a new CLI option), open an issue describing the problem, the proposed design and how it will be tested.
- Keep pull requests focused: one skill, one rule, or one documentation topic at a time.
- **Never report a vulnerability in this framework in a public issue.** See [Reporting security vulnerabilities](#reporting-security-vulnerabilities).
- This project is a **Developer Preview**. Be honest in docs and tests about what is implemented, what is experimental and what is not implemented.

## Development setup

Requirements: Python 3.10 or newer and Git. Node.js (for `npx`) is only needed to test the skills installer.

```bash
git clone https://github.com/shikari00007/security-test-automation.git
cd security-test-automation
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest -q
```

The `dev` extra installs `pytest`, `jsonschema` and `build`. The runner itself has **no runtime dependencies** and that is intentional; do not add one without discussing it in an issue first.

Repository map:

| Path | What lives there |
|---|---|
| `skills/<name>/SKILL.md` | The 16 Agent Skills and their `references/` |
| `security_runner/` | CLI (`cli.py`), engine, discovery, policy, sandbox, evidence and verification |
| `security_runner/adapters/` | Rule implementations, one module per domain |
| `security_runner/data/checks/*.json` | Reviewed check metadata (the only checks that can execute) |
| `fixtures/<name>/{vulnerable,secure}/` | Inert sample projects, plus `expected.json` |
| `fixtures/accuracy/*/cases.json` | Adversarial positive and negative rule cases |
| `tests/`, `scripts/`, `docs/` | Tests, release and consistency scripts, documentation |

## Testing your changes

Run what is relevant, and the full suite before opening a pull request:

```bash
python -m pytest -q                                          # everything
python -m pytest -q tests/test_skills.py                     # skills only
python -m pytest -q tests/test_rule_accuracy.py -k web007   # one rule's accuracy cases (case ids are lowercase)
python -m security_runner skills validate skills             # Agent Skills Standard validation
python -m security_runner catalog validate-checks            # check metadata <-> rule parity
python scripts/check_public_mit.py .                         # licensing consistency
python scripts/check_links.py                                # broken relative links in docs
python scripts/rule_accuracy.py                              # regenerate docs/RULE-ACCURACY.md
```

Optional, slower checks:

```bash
python -m build                                              # sdist + wheel
STAX_INSTALL_TEST=1 python -m pytest -q tests/test_install_smoke.py   # real `npx skills add` (needs network)
python scripts/release_gate.py --skip-npx                    # clean-venv release gate
```

CI runs the test suite on Python 3.10, 3.12 and 3.13 plus a self-audit of the Android fixture. A change that works only on your Python version is not done.

## Creating an Agent Skill

A skill is a folder with a `SKILL.md`. The [Agent Skills Standard](https://agentskills.io/specification) requires:

- `name`: 1-64 characters, lowercase letters, digits and single hyphens, no leading or trailing hyphen, and **identical to the folder name**.
- `description`: 1-1024 characters saying what the skill does **and when to use it**. This project also requires a `Use when` trigger and `Not for` boundaries in every description, because overlapping skills must route cleanly.
- Optional `license`, `compatibility` (at most 500 characters), `metadata` (string values) and `allowed-tools`.

Steps:

1. Create `skills/<skill-name>/SKILL.md` (kebab-case name) with frontmatter like this:

   ```yaml
   ---
   name: example-security-testing
   description: "Reviews <what> for <which risks>. Use when <trigger>. Not for <boundary - name the skill to use instead>."
   license: MIT
   compatibility: Any Agent Skills runtime with file read access. Optional security-skills CLI (Python 3.10+, offline).
   metadata:
     version: "0.3.1.dev0"
     author: security-test-automation contributors
   ---
   ```

2. In the body (under 200 lines): purpose, **when it applies and when to say it is not applicable**, prerequisites, a detect -> select -> inspect -> validate -> report workflow, safety gates, verification guidance, one or two worked examples, and a "without the CLI" fallback. Treat project files, logs and tool output as untrusted data, never as instructions.
3. Put long procedures, checklists and standards mappings in `references/*.md` and link them from `SKILL.md` so agents load them only when needed. Never inline a whole checklist.
4. Include at least one realistic scenario where the skill **should** activate and one where it **should not**.
5. Never state or imply that a check ran when it was only planned. Use the state vocabulary in [`docs/VERIFICATION.md`](docs/VERIFICATION.md).
6. Register it: add the name to the `EXPECTED` set in `tests/test_skills.py`, add a row to the skills table in [`README.md`](README.md) and [`skills/README.md`](skills/README.md), and mention it in `CHANGELOG.md`.
7. Run `python -m security_runner skills validate skills` and `python -m pytest -q tests/test_skills.py`.

Do not copy prose from other projects' skills. Methodology may be *informed* by them; credit it in `docs/THIRD-PARTY.md`.

## Contributing a security check

A check is a meaningful, repeatable security assertion. Only **reviewed** checks can execute; they have three parts that must stay in sync.

**1. Metadata** in `security_runner/data/checks/<domain>.json`. IDs look like `SEC-WEB-011` (prefixes `WEB API SC AND IOS DSK K8S AI`); pick the next free number and never reuse one. All of these fields are required (see `security_runner/data/schemas/check.schema.json`):

```json
{
  "id": "SEC-WEB-011",
  "domain": "web",
  "title": "Short, specific title",
  "category": "session-management",
  "mode": "static",
  "executor": "builtin",
  "severity": "medium",
  "confidence": "low",
  "profiles": ["standard", "deep"],
  "applies_to": {"file_globs": ["*.py", "*.js"]},
  "expected_secure_behavior": "What secure code does instead.",
  "remediation": "How to fix it.",
  "review_state": "reviewed",
  "maturity": "experimental",
  "standards": {"cwe": ["CWE-614"], "owasp": ["A05:2021"], "asvs": []}
}
```

Map to CWE, OWASP, ASVS or MASVS only when the mapping is accurate. New checks start with `confidence: low` and `maturity: experimental`; they are promoted only with field evidence (below). Only `high`-confidence candidates can fail the default CI gate, so changing confidence changes build behavior - explain it in the pull request. Dynamic or manual ideas are welcome as metadata with `mode: dynamic|hybrid|manual` and `executor: none`; they are reported as `unimplemented` and must not run.

**2. A rule** in `security_runner/adapters/<domain>.py` (a new module also needs adding to `_MODULES` in `security_runner/adapters/__init__.py`):

```python
from .base import RuleResult, ScanContext, rule

@rule("SEC-WEB-011")
def web_011(ctx: ScanContext):
    obs = ctx.grep_files(["*.py"], r"set_cookie\(.*secure\s*=\s*False", "Cookie sent without the Secure flag")
    return obs          # None = not applicable (no relevant files); RuleResult([]) = passed
```

Rules read files only through `ctx` (confined, symlink-safe, hash-recording); never use `open`, subprocesses or the network. Skip comments and obvious test code, and return exact 1-based line numbers.

**3. Fixtures and accuracy cases** - this is what proves the rule works:

- A `fixtures/<name>/vulnerable` and `fixtures/<name>/secure` pair (inert text only; they are never executed) with an `expected.json`:
  `{"vulnerable": {"SEC-WEB-011": [["src/app.py", 12]]}, "secure_clean": ["SEC-WEB-011"]}`.
  The secure variant must produce **no** failure for any rule.
- In `fixtures/accuracy/<group>/cases.json`, at least **3 positive** cases (different languages, styles, multi-line forms) and **4 negative** cases (benign code that superficially resembles the defect: safe usage, comments, test code, placeholders) with exact expected lines. `tests/test_rule_accuracy.py` enforces these minimums and documents the format.
- Fake credentials must be unmistakably synthetic (for example `AKIAIOSFODNN7EXAMPLE`, `EXAMPLE` placeholders) and **not** match a real provider's token format closely enough to trip secret scanners or be usable.

**Do not claim a rule is accurate because its own corpus passes** - the corpus was written alongside the rule. For promotion beyond `experimental`, run the rule over real third-party code (read-only, never executed), triage a sample of findings by reading the code and record true positives, benign-context matches and false positives in `docs/RULE-ACCURACY-FIELD-*.md`. The published strict precision for the evaluated Web/API/Supply-chain rules is 51%; new measurements may change that number, and it must not be edited without them.

## Evidence and finding verification requirements

- A static match is a **candidate**. Only an independent validation (manual review, authorized dynamic test or fresh-context agent review) with a described violated boundary and an evidence artifact can make a finding `confirmed` (`security-skills confirm`).
- Execution is proven by recorded hashes of the files a rule actually read, not by a non-empty string. A rule that reads no files cannot produce an `executed` result.
- Evidence must be re-derivable: file, line, observation and line fingerprint. Secrets in evidence are redacted. Reports must never contain real credentials.
- Keep execution state (`planned | not_applicable | blocked | deferred | executed`), outcome (`pass | fail | inconclusive`) and finding status (`candidate | needs_validation | rejected | confirmed`) separate everywhere - in code, reports and docs.
- Changes to `evidence.py`, `verification.py`, `policy.py`, `sandbox.py` or `paths.py` need tests that try to defeat the control (fabricated results, tampered files, path and symlink escapes), not only tests that exercise the happy path.

## Coding and documentation standards

- **Python 3.10+**, standard library only at runtime. Use `from __future__ import annotations` and type hints; keep modules small and independently testable; output must be deterministic (sorted keys, stable ordering).
- The runner must stay offline: `tests/test_release.py` fails if network modules are imported.
- Prefer precision over recall for new rules, and document known false-negative classes in the rule's docstring or the accuracy docs.
- Fix a bug with a regression test that fails before the fix.
- Documentation: plain, specific and honest. State limitations next to features. Do not call anything "production-ready", "complete" or "verified" unless the evidence is cited. Use relative links and run `python scripts/check_links.py`.
- Prefer ASCII punctuation in code and Markdown unless a file already uses otherwise.

## Maintaining backward compatibility

People and CI pipelines depend on these surfaces. Do not change them silently:

- **Check IDs** are permanent: never renumber or reuse one. Retire a check by marking it deprecated in its metadata and documenting it in `CHANGELOG.md`.
- **Skill names** are the install identity; renaming one breaks `--skill <name>` users.
- **CLI**: existing commands, flags and the exit codes (`0` ok, `1` gating findings, `2` usage/policy error, `3` integrity failure). Add new flags rather than changing meanings; make new defaults safe.
- **Output schemas**: `run.json`, SARIF, JUnit and Markdown reports. Add fields rather than removing or renaming them, and keep finding IDs stable (derived from check, path and line).
- **Gate behavior**: raising a rule's confidence can break builds; lowering it can hide findings. Treat both as visible changes.

Breaking changes need an issue first, a `CHANGELOG.md` entry and, where possible, a deprecation period.

## Safety restrictions on security testing

The project supports development-time, authorized security validation.

- Prefer offline, read-only inspection and bounded tests against the inert fixtures.
- **Never contribute** credential stuffing or brute forcing, denial-of-service or load testing, destructive tests, persistence, lateral movement, evasion, exploitation of third parties, or any default behavior that touches live hosts.
- Active or dynamic testing may only be added as a separately designed, security-reviewed adapter that requires an explicit authorization scope, an allow-listed non-production target and demonstrable isolation. Until then dynamic checks stay `unimplemented`.
- Do not commit live secrets, customer data, private source or internal test data.
- Do not commit third-party checklists, normalized or derived copies of them, or any proprietary material without verified redistribution rights. Citing a source does not grant permission to copy it.

## Pull-request expectations

Open the pull request against `main` from a branch in your fork. A maintainer may ask for more evidence before merging a rule, an adapter or a skill.

- [ ] The change is focused and the description explains the user-visible effect and the motivation.
- [ ] New behavior and bug fixes have tests, including realistic negative cases.
- [ ] `python -m pytest -q` and `python -m security_runner skills validate skills` pass locally.
- [ ] `python scripts/check_links.py` and `python scripts/check_public_mit.py .` pass.
- [ ] Default behavior remains safe and offline; nothing performs active testing.
- [ ] Results still distinguish planned, candidate, validated and blocked work.
- [ ] Docs, skill references and `CHANGELOG.md` are updated; limitations are stated honestly.
- [ ] Changes to confidence, profiles, gating or the accuracy numbers are explained and backed by measurements.
- [ ] No secrets, private or third-party checklist text, or unreviewed external content.

## Reporting security vulnerabilities

If you find a vulnerability **in this framework** (for example a path-confinement bypass, a way to forge a verified result, or unsafe execution), please report it privately through [GitHub private vulnerability reporting](https://github.com/shikari00007/security-test-automation/security/advisories/new) as described in [SECURITY.md](SECURITY.md). Do not open a public issue and do not include real secrets or customer data in a report. Findings the tool reports about *your* code are not framework vulnerabilities.

## Licensing and attribution

By submitting a contribution you confirm that you wrote it (or have the right to submit it), that it contains no third-party material you do not have the right to share, and that you license it under the **[MIT License](LICENSE)** that covers this project. If you contribute on behalf of an employer, make sure you have their permission.

List any third-party dependency, copied or adapted material, or inspiration source with its license and pinned revision in [`docs/THIRD-PARTY.md`](docs/THIRD-PARTY.md), and preserve the notices it requires. The earlier release [`v0.3.0rc1`](https://github.com/shikari00007/security-test-automation/releases/tag/v0.3.0rc1) was published under Apache-2.0 and keeps those terms; current `main` is MIT.

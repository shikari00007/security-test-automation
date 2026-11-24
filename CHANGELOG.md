# Changelog

## Unreleased (0.3.1.dev0) - public mainline refresh
- **License:** current mainline relicensed from Apache-2.0 to **MIT** (Copyright (c) 2026 shikari00007). The historical `v0.3.0rc1` release remains Apache-2.0 and unchanged. Package metadata (`License-Expression: MIT`), all 16 `SKILL.md` files, `LICENSE`, `NOTICE`, `CONTRIBUTING.md` and `docs/THIRD-PARTY.md` updated.
- **Docs:** README rewritten (install, prompts, agents, skills catalog, domains, profiles, CLI, workflow, regression testing, limitations); CONTRIBUTING expanded (setup, creating a skill, contributing a check, verification and compatibility rules); SECURITY.md now points at private vulnerability reporting; issue and PR templates added.
- **Skills:** removed stale "not yet published" wording (the CLI installs from GitHub: `pip install git+https://github.com/shikari00007/security-test-automation.git`); added the missing Developer Preview banner to `ai-llm-security`.
- **Tooling:** `scripts/check_links.py` (relative links and anchors), `scripts/check_public_mit.py`, release gate now verifies MIT metadata in the wheel and sdist and no longer requires the private raw inventory unless `--require-restricted-scan` is passed.
- Accuracy numbers are unchanged (51% strict precision for the evaluated Web/API/Supply-chain rules).

## 0.3.0rc1 - Developer Preview release candidate
- **Findings semantics:** static rule matches are *candidates*. Automatic re-execution never produces `confirmed`; `security-skills confirm` records an independent validation (validator, method, violated boundary, evidence hash) and verification rejects `confirmed` without it. Default CI gate = reproduced high-confidence candidates; `--gate confirmed` gates only validated findings. Regression generation from a candidate needs `--accept-candidate` and is labelled.
- **Maturity labels:** every check is `preview`, `experimental` (4 AI/LLM rules) or `unimplemented` (15 dynamic/hybrid/manual checks + external adapters). Playwright/Schemathesis outputs are experimental skeletons.
- **Rule accuracy:** adversarial corpus (`fixtures/accuracy/`, 524 cases, >=3 positive and >=4 negative per rule) plus field triage on public code. Field strict precision for web/API/supply-chain was 51% (85% counting intentional/benign patterns); confidence of low-precision rules (SC-001, SC-006, WEB-002, WEB-005 -> low; WEB-006, WEB-007, API-004 -> medium) was lowered and they leave the Quick profile. See docs/RULE-ACCURACY*.md.
- **Bugs found by the accuracy work:** line-number shift after comments in shared comment stripper; flow-style YAML, multi-line HCL, Kotlin and JSON-key variants missed; many false positives (debug source sets, library manifests, Helm templates, placeholders, minified bundles).
- **AI/LLM:** original methodology (docs/methodology/ai-llm.md) independently reviewed (docs/methodology/ai-llm-REVIEW.md, APPROVE WITH CHANGES); all required changes applied; added experimental SEC-AI-004. The post-change code was not re-reviewed independently.
- **Release engineering:** allowlist build (`scripts/build_release.py`), restricted-content scanner, clean-install release gate (`scripts/release_gate.py`), Apache-2.0 + NOTICE. Third-party checklists and the normalized catalog are excluded from the public tree.
- Earlier in 0.3.0 development: 11 foundation defects fixed (docs/PHASE0-AUDIT.md), runner/engine/verification/reporting/regression, 16 skills, 8 domains.
## 0.2 / 0.1
Plan-only foundation (superseded).

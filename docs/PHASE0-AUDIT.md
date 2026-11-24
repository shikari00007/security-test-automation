# Phase 0 - foundation audit (v0.2 ZIP) and disposition

Inputs: `docs/baseline/security-test-automation-prekickoff-v0.2.zip` (35 files; extracted to an isolated directory, never executed in place) and the v0.3 audit. **The audit describes a v0.3 `scripts/` tree (`coverage_report.py`, `select_checks.py`, 7,191-entry inventory) that is not in the supplied ZIP**, so P0-05 (`evidence=['fake']`), P1-07 etc. could not be reproduced on the supplied code; their *intent* was re-implemented and tested instead. Reported counts were not trusted: everything below was recomputed.

## Defects reproduced in the v0.2 ZIP -> fixed (regression tests in tests/test_core_engine.py)
| # | Defect | Fix |
|---|---|---|
| 1 | `pip install` broke the CLI (catalog resolved outside the package) | data moved into `security_runner/data`, package-data declared; wheel install verified in a clean venv |
| 2 | `__version__` 0.1.0 vs pyproject 0.2.0 | single version, tested |
| 3 | Quick profile silently dropped detected cloud-kubernetes / ai-llm checks (list truncation) | plan lists every check with status+reason; no truncation |
| 4 | Output guard bypass via symlinked directory (wrote into the target) | parent resolved before comparison |
| 5 | Fixtures under the install root could not be scanned | guard removed (output confinement is what matters) |
| 6 | Substring dependency detection (`dmcpkg` -> ai-llm) | whole-name matching |
| 7 | Domain registry marked 6 core domains `conditional: true` | `classification` + correct `conditional` (only cloud-k8s, ai-llm) |
| 8 | Check schema never enforced | schema + rule/metadata parity validated in tests and CI |
| 9 | Skills named differently from required set; only prefix checked | 16 required skills; full Agent Skills spec validator |
| 10 | Skills depended on a repo checkout (`python3 -m security_runner`) that `npx skills add` does not install | skills work standalone with a manual fallback; CLI optional |
| 11 | Plan "verification" accepted any self-consistent hash | evidence is re-derived from target files; see VERIFICATION.md |

Found later by release gates / accuracy work: verification re-hashed only the originally recorded byte count, so appending to an examined file went undetected (fixed, regression test); the shared Python comment stripper shifted line numbers after comments (fixed, tests).

Also found during real-code auditing (Phase 3): per-finding rule re-execution made verification O(findings x scan) (45 s -> cached per check), and SEC-WEB-007 false positive on `CERT_REQUIRED if x else CERT_NONE` (fixed + test).

## Unresolved
- Source rights for the supplied checklists unconfirmed; they and all derived catalog data are excluded from the public release.
- WEB -1 "Cookie Security Deep" declares 96 checks but the file ends after 29 (source truncated; flagged, not invented).
- Heuristic canonical metadata (testing mode, standards, flags) is unreviewed; reviewed->canonical links not made.
- Rule false-positive rates on real code are only spot-checked (see CHANGELOG), not measured.

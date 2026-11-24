# Release gates - Developer Preview 0.3.0rc1

Automated by `python scripts/release_gate.py` (builds the public tree from an allowlist, then exercises it from clean venvs; latest report in `dist/release-gate-report.md`). Nothing has been published.

| Gate | Scope | Status |
|---|---|---|
| G1 content | Allowlist excludes catalog/raw*, canonical catalog, baseline docs, importer; manifest hashes; no reproduced checklist text (scanner has positive-control tests); Apache-2.0 + NOTICE; pinned upstream SHAs; Developer Preview label | Automated, passing |
| G2 packaging | sdist + wheel build from the release tree; wheel contains package data + licence files, no tests/fixtures/catalog | Automated, passing |
| G3 clean install | Version, skill validation, check-data loading from the installed wheel; all 8 fixture pairs audited **inside a no-network namespace**; evidence integrity (fabricated executed result, fake evidence string, post-run file change including appended bytes); path security (output inside target, symlinked output dir, symlinked inputs, bad targets); scope policy (no scope, production, valid scope still unimplemented); regression red/green | Automated, passing |
| G4 tests | Full pytest suite on the release tree in a clean venv | Automated, passing |
| G5 agents | `npx skills add <release tree>` for claude-code, codex, cursor, gemini-cli, github-copilot: skills are copied byte-identical and spec-valid into `.claude/skills` and `.agents/skills` (the installer maps the other agents onto these directories); `skills list`; single-skill install | Automated, passing. Verifies installation/discovery files only - **no live agent session loaded the skills** |
| G6 published install | `npx skills add shikari00007/security-test-automation` from GitHub (`scripts/verify_published.sh`) | **PENDING - repository not published** |

## Open risks (not release-blocking for a Developer Preview, but known)
1. **Rule precision.** Field triage of the web/API/supply-chain rules: 51% strict / 85% pattern-level precision (282 sampled findings); some rules are far lower (SC-001, WEB-002, WEB-005, SC-006). Their confidence is `low` and they are excluded from Quick and from the default CI gate. Mobile/desktop/cloud: 100% after fixes, but tuned on the sampled repos, which lean intentionally vulnerable. AI/LLM: 0 findings on five repos, i.e. recall unmeasured. Corpus numbers (0 FP/FN) are by construction.
2. **No dynamic testing, no external tool adapters** (unimplemented, labelled).
3. **AI/LLM methodology** was independently reviewed (APPROVE WITH CHANGES) and changes applied, but the post-change rules/docs were not re-reviewed.
4. **Rights:** the maintainer confirmed ownership of the original content for Apache-2.0 on 2026-11-24 (third-party checklists excluded). This is the maintainer's attestation; it has not been independently verified.
5. **GitHub push protection** may flag synthetic token-shaped strings in fixtures/tests (`ghp_...`, `xoxb-...`, PEM blocks); `.github/secret_scanning.yml` excludes those paths, but push protection behaviour is untested until a real push.
6. **Agent-runtime loading** not tested in live Claude Code/Codex/Cursor/Gemini sessions.
7. **CI workflow** (`.github/workflows/validate.yml`) has not run on GitHub.
8. Hash-chained manifests are tamper-evident only unless `--hmac-key-env` is used.

# Source rights, attribution and upstream pinning

| Source | License (read from GitHub license metadata, 2026-11-20) | Pinned revision | How used |
|---|---|---|---|
| petrkindlmann/qa-skills | MIT | `5087a3461d49da76b1e794d9b0bfbd23f38dc75b` | Architectural/usability reference only (skill granularity, routing, start/do pattern). No text or code copied. |
| cloudflare/security-audit-skill | MIT | `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8` | Methodology reference (phased audit, coverage accounting, adversarial verification). No code or text copied; not a runtime dependency. |
| SnailSploit/Claude-Red | MIT | `6196ba7464662de34e8744d359f175d1a7bca530` | Reference only. Offensive workflows are neither imported nor enabled. |
| agentskills.io specification | Public specification | fetched 2026-11-20 | Implemented by `security_runner/skillcheck.py`. |
| OWASP LLM Top 10 (2025), CWE, OWASP ASVS/MASVS, MCP specification | Public standards, referenced by identifier/title only | - | Cited in `docs/methodology/ai-llm.md` and check metadata. |
| Third-party test/sample repositories used for field accuracy checks | Various open-source licenses | see `docs/RULE-ACCURACY-FIELD*.md` | Read-only static input, never executed; no content redistributed. |

**Third-party checklists are not part of this repository.** Source checklists supplied to the maintainers were used privately to inform the catalog design; redistribution rights have not been confirmed, so neither their text nor derived normalized entries are published. A release-time scanner (`scripts/scan_restricted.py`) checks the published tree for reproduced checklist text against the private inventory.

## Licensing of this project

**Current mainline: MIT License, Copyright (c) 2026 shikari00007** (see `LICENSE`, `NOTICE`).

- The maintainer, who is the sole author of the repository history (verified from the commit log and the GitHub contributors list), confirmed on 2026-11-24 that they own the rights to the original code, skills, documentation, fixtures and AI-assisted contributions, and re-confirmed the intent to relicense current `main` under MIT on 2026-11-25. This is the maintainer's attestation; it has not been independently verified.
- **Historical release:** `v0.3.0rc1` was published under Apache-2.0 and keeps those terms. Permissions already granted under Apache-2.0 are not revoked.
- No third-party code, text or media is vendored. The upstream projects above are MIT-licensed methodology references; nothing was copied, so no upstream notice is reproduced beyond this attribution.
- Third-party security checklists used privately during development, and any normalized or derived copies, are **not** part of this repository (redistribution rights unconfirmed).
- Future contributions are accepted under MIT (see `CONTRIBUTING.md`); contributors must record any third-party material here with its license and pinned revision.

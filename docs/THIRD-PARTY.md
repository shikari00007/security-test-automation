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
Original code, skills, documentation, fixtures and AI-assisted contributions: **Apache-2.0**, Copyright 2026 shikari00007. The maintainer has confirmed (2026-11-24) that they own or have the necessary rights to license this original content. This confirmation excludes third-party security checklists and any external material without verified redistribution rights; those are not part of this repository.

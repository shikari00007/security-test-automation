# Ranking, responses and test mapping

## Impact x likelihood rubric

Score each 1-3. Write the reasoning in the Why cell. Risk = impact x likelihood; bands Low 1-2, Medium 3-4, High 6-9 (possible products are 1, 2, 3, 4, 6, 9). This is a deliberately coarse scale, consistent with the OWASP Threat Modeling Cheat Sheet's "likelihood multiplied by impact" ranking, which itself notes both are hard to estimate. It is judgement, not measurement.

| Score | Impact | Likelihood |
| --- | --- | --- |
| 3 | Cross-tenant or bulk data exposure, account takeover, money loss, safety, or full service outage | Reachable by anonymous or any authenticated user, low skill, automatable, or already seen in the wild against similar apps |
| 2 | One user's or one tenant's data, bounded financial loss, partial or temporary outage | Needs an authenticated privileged user, some skill, or a specific precondition |
| 1 | Minor, easily reversed, no sensitive data | Needs insider access, multiple unlikely conditions, or physical access |

Reasoning checklist for Why: who can reach it, what skill or precondition, blast radius, existing controls, confidence (confirmed in code versus assumed). If a score rests on an assumption, say so and add it to Open questions.

Ordering ties: higher impact first, then cheaper mitigation first. Remediation effort is a legitimate secondary factor but is not part of the score.

## Response options

| Response | Use when | Record |
| --- | --- | --- |
| Eliminate | Remove the feature, data or flow | Status `eliminated`, with what was removed |
| Mitigate | A control reduces likelihood or impact | Control and location in Mitigation; test in Test |
| Transfer | A provider or contract owns the control | Which party, which assurance; still test your side of the boundary |
| Accept | Residual risk is tolerable | Named owner and revisit trigger in Why; status `accepted` |

## Threat to test mapping

Every row's Test cell names: level, setup, expected result. Prefer tests that fail when the mitigation is removed.

| Threat type | Test idea | Level | Hand off to |
| --- | --- | --- | --- |
| Cross-tenant or cross-user object access | Matrix over users A1, A2, B1 x every verb on the resource; B1 gets 404 or 403 and state unchanged | Authorization / integration | security-regression-generation after a fix; `api-security-testing` for dynamic checks (needs scope) |
| Role or function escalation | Each role x each privileged endpoint; expected status per role from the model | Authorization matrix | same |
| Mass assignment | Send a non-writable field, assert response ignores it and stored value unchanged | Integration | same |
| Webhook or signature checks | Missing, wrong and stale signature each rejected with no side effect; replay is a no-op | Unit | security unit tests |
| Input to interpreter (SQL, HTML, shell) | Harmless marker with quote or tag characters stored literally or rendered inert | Unit / component | `web-security-testing` for dynamic |
| Rate limit, lockout | Fake clock and in-memory limiter; Nth attempt refused. Never load-test a live system without scope | Unit / integration | security unit tests |
| Size, count, timeout limits | Over-limit request refused; configuration assertion on limits | Unit / config | `api-security-testing` (config review) |
| Audit and repudiation | Action emits exactly one event with actor id; no update or delete path | Integration | security unit tests |
| Secrets, tokens in logs or URLs | Log scrubber test; assertion that tokens are absent from URLs | Unit | security unit tests |
| Privacy (LINDDUN) | Payload allowlist on analytics; retention job deletes expired rows | Unit / integration | security unit tests |
| LLM and agent threats | Injection marker in retrieved text does not trigger tool call; output is escaped | Eval / integration | `ai-llm-security` |
| Third-party component risk | Lockfile, provenance and audit checks | Pipeline | `supply-chain-security` |
| Cloud or deployment boundary | Policy and config assertions on network, buckets, IAM | Config review | `cloud-kubernetes-security` |
| Cannot be tested automatically | Design-review checklist item with owner, listed in Handoffs | Review | none; say so |

Tests that do not exist yet are `proposed`; say so rather than implying coverage. When `security-unit-testing` or an authorization-testing skill from this suite is not installed, write the test directly in the project's framework (pytest, Jest, Vitest, JUnit) following the project's existing test layout.

## Standards and editions used

| Reference | Edition and verification |
| --- | --- |
| STRIDE | Microsoft Threat Modeling Tool threat page (Microsoft Learn, page updated 2026-03, fetched 2026-11): Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege |
| OWASP Threat Modeling Cheat Sheet | cheatsheetseries.owasp.org, fetched 2026-11: four questions, four steps, rank by likelihood x impact, respond with mitigate / eliminate / transfer / accept |
| Threat Modeling Manifesto | threatmodelingmanifesto.org, fetched 2026-11: "What are we working on? What can go wrong? What are we going to do about it? Did we do a good enough job?" |
| LINDDUN | linddun.org/threat-types (DistriNet, KU Leuven), fetched 2026-11; seven categories listed in the prompts file; site shows no version |
| OWASP LLM Top 10 | 2025 edition (LLM01:2025 to LLM10:2025), genai.owasp.org, fetched 2026-11 |
| OWASP ASVS 4.0.3 (V1 Architecture) | github.com/OWASP/ASVS tag v4.0.3, `0x10-V1-Architecture.md`: 1.1.2 threat modeling for every design change or sprint planning; 1.1.3 functional security constraints in user stories; 1.1.4 documentation and justification of trust boundaries, components and significant data flows; 1.1.5 definition and security analysis of the high-level architecture and connected remote services; 1.14.1 segregation of components of differing trust levels. |
| OWASP ASVS 5.0.0 | Released 2025-05-30 (asvs.owasp.org; github tag v5.0.0). The V1 chapter is now "Encoding and Sanitization"; there is no dedicated threat-modeling requirement. The 5.0 "For users of 4.0" notes say documented security decisions evolved from 4.0's policy and threat-modeling requirements. Relevant 5.0.0 items: 15.1.x documentation of components and resource-heavy functionality; 6.1.1 documented anti-automation; 8.1.1 authorization documentation; 8.2.1 function-level, 8.2.2 data-specific access; 8.3.1 server-side enforcement; 8.4.1 cross-tenant controls; 14.1.1 classify sensitive data; 16.3.2 failed authorization logged |
| CWE | cwe.mitre.org definitions, fetched 2026-11 (ids in the prompts file) |

Cite requirements with the version prefix (`v5.0.0-8.2.2`, `v4.0.3-1.1.2`) because ASVS ids change between releases. The exact requirement wording is in the ASVS files; this skill paraphrases.

# STRIDE, LINDDUN and LLM prompts

Use these as questions to ask at each boundary crossing, data store and process, then write only the ones that apply as abuse cases. Prompts find categories; business-logic abuse (price tampering, coupon reuse, workflow skipping) must be added by reading the product rules.

## STRIDE (Microsoft SDL threat categories)

Source: Microsoft Learn, "Threats - Microsoft Threat Modeling Tool" (STRIDE model table), fetched 2026-11; the property-violated column is the conventional SDL mapping and is not taken from the OWASP cheat sheet.

| Letter | Threat | Property violated | Question at a boundary | Typical mitigation family | Typical test |
| --- | --- | --- | --- | --- | --- |
| S | Spoofing | Authentication | Can the caller pretend to be another user, service or provider? Is every entry authenticated the same way? | Single vetted auth mechanism, signature verification, mTLS, rate limiting | Request without or with a bad credential or signature is refused; throttle returns 429 |
| T | Tampering | Integrity | Can data be changed in transit, at rest, or by a field the user should not control? | Server-side validation, allowlisted fields, integrity checks, parameterised queries | Unwritable field stays unchanged; modified signature or body is rejected |
| R | Repudiation | Accounting (non-repudiation) | Could an actor deny an action and nothing could prove otherwise? | Append-only audit events with actor, action, target, time | Action produces exactly one audit row with the actor id |
| I | Information disclosure | Confidentiality | Who can read this data, error, log, URL or cache entry that should not? | Authorization per object and tenant, encryption, minimal logging, generic errors | Other tenant gets 404; error body has no stack trace; log lacks token |
| D | Denial of service | Availability | What is unbounded: size, count, time, fan-out, cost? | Limits, quotas, timeouts, pagination caps, async queues | Over-limit input refused; configuration assertion on limits (no live load tests) |
| E | Elevation of privilege | Authorization | Can a lower role reach a higher role's function or another tenant's object? Does a client-side check stand in for a server one? | Central server-side authorization, deny by default, field allowlists | Authorization matrix over roles x endpoints x tenants |

Per element type (a DFD heuristic, not a rule):

| Element | Check first |
| --- | --- |
| External entity (browser, partner) | S, R |
| Process (API, worker) | S, T, R, I, D, E |
| Data store | T, I, D, R (is access logged?) |
| Data flow crossing a boundary | T, I, D |

## Question bank by common feature

| Feature | Ask |
| --- | --- |
| Login, reset, invite | Enumeration by response difference; token entropy, expiry, single use; link built from trusted config not headers |
| Any `/:id` resource | Is the object looked up by id alone or by id and owner and tenant? List endpoints and exports too |
| File upload and download | Size and type limits, storage keys unguessable, served with safe content type, who can fetch, URL lifetime |
| Webhook or callback | Authenticity (signature, timestamp), replay, idempotency, what the handler may change |
| Outbound fetch of user URLs | Can it reach internal addresses or metadata endpoints; allowlist and redirects |
| Admin or support tooling | Who can use it, is it logged, does it bypass tenant scoping |
| Background jobs and queues | Who can enqueue, does the job re-check authorization at run time, poison messages |
| Secrets and config | Where stored, who reads, rotation, present in logs or client bundle |
| Third-party scripts or SDKs | What data they receive, integrity of the loaded code (hand off to `supply-chain-security`) |

## LINDDUN (privacy threats)

Use when the feature collects, stores or shares personal data. Categories as named at linddun.org/threat-types (DistriNet, KU Leuven; fetched 2026-11, page shows no version number):

| Category | Ask |
| --- | --- |
| Linking | Can records, sessions or datasets be joined to connect a person's activities? |
| Identifying | Can a person be singled out from supposedly anonymous or pseudonymous data? |
| Non-repudiation | Is there proof of a person's action that they would reasonably want to deny, kept longer than needed? |
| Detecting | Can an observer infer that a person is a user or took part, from existence, size or timing of data? |
| Data disclosure | Is personal data exposed to parties who do not need it, including third-party SDKs and logs? |
| Unawareness and unintervenability | Do people know what is collected and can they access, correct, object or delete? |
| Non-compliance | Does processing diverge from policy, consent or legal obligations (retention, purpose, transfers)? |

Note the overlap: "non-repudiation" is a privacy threat in LINDDUN (a person may need deniability) while "repudiation" in STRIDE is a security threat (an actor denies an action). Record which lens a row uses in the Category cell, for example `LINDDUN data disclosure`. Legal compliance conclusions need a privacy professional; this only surfaces design risks.

## OWASP Top 10 for LLM Applications 2025 (when an LLM or agent is present)

Source: genai.owasp.org/llm-top-10, edition 2025, fetched 2026-11. Treat the model as an untrusted process whose inputs include retrieved documents and tool output.

| Id | Name | Boundary question |
| --- | --- | --- |
| LLM01:2025 | Prompt Injection | Which untrusted text (user, web page, document, tool result) can reach the prompt, and what can the model do afterwards? |
| LLM02:2025 | Sensitive Information Disclosure | What sensitive data is in context, training or retrieval that another user could elicit? |
| LLM03:2025 | Supply Chain | Which models, datasets, plugins and libraries are third-party? |
| LLM04:2025 | Data and Model Poisoning | Who can write to training, fine-tuning or retrieval data? |
| LLM05:2025 | Improper Output Handling | Is model output rendered, executed or passed to an interpreter without validation? |
| LLM06:2025 | Excessive Agency | Which tools and permissions does the agent hold, and does a human approve the destructive ones? |
| LLM07:2025 | System Prompt Leakage | Does the system prompt contain secrets or authorization logic? |
| LLM08:2025 | Vector and Embedding Weaknesses | Is retrieval filtered by the caller's permissions and tenant? |
| LLM09:2025 | Misinformation | Does a user or process act on output without verification where errors are costly? |
| LLM10:2025 | Unbounded Consumption | Are tokens, calls, cost and tool loops capped per user? |

Hand execution of LLM tests to `ai-llm-security`.

## Writing an abuse case

Template: `<actor with stated privilege> <does action using which flow> to <gain what>, because <missing or weak control>`. Good: "A member of workspace A calls GET /api/notes/42 with a note id from workspace B and reads it because lookup is by id only." Weak: "Broken access control." Each abuse case must be testable as one observable assertion.

## Common CWE anchors (verified at cwe.mitre.org, fetched 2026-11)

CWE-639 Authorization Bypass Through User-Controlled Key; CWE-862 Missing Authorization; CWE-285 Improper Authorization; CWE-306 Missing Authentication for Critical Functionality; CWE-352 Cross-Site Request Forgery; CWE-770 Allocation of Resources Without Limits or Throttling; CWE-117 Improper Output Neutralization for Logs. Cite only when it adds precision; the abuse case matters more than the id.

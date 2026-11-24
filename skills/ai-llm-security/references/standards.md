# Standards

- OWASP Top 10 for LLM Applications (2025 edition: LLM01 Prompt Injection through LLM10 Unbounded Consumption). Cite the edition; the 2023 list is numbered differently.
- MITRE ATLAS as context for adversarial ML threats; cite as context only. Agentic-specific OWASP material is not cited here until its exact title and version are verified.
- NIST AI RMF as governance context, not a test standard.
- CWE: CWE-77/78 command injection (via output handling), CWE-200 information exposure, CWE-285 improper authorization, CWE-74 injection, CWE-1427 improper neutralization of input used for LLM prompting (cite when it matches).
- CWE-1426 Improper Validation of Generative AI Output is the primary mapping for output handling (SEC-AI-001), with CWE-94/78/89/79 as downstream consequences. CWE-250 (execution with unnecessary privileges) covers dangerous tools and over-broad MCP filesystem scope (CWE-732 is about permissions on a resource and is not used). Also used: CWE-502 (pickle loading), CWE-532 (logs), CWE-639, CWE-798, CWE-829, CWE-494 (approximate), CWE-770/CWE-400. Mappings were reviewed in `docs/methodology/ai-llm-REVIEW.md`.

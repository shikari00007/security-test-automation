# AI/LLM methodology (OWASP Top 10 for LLM Applications, 2025 naming)

- LLM01 Prompt Injection: untrusted text (user, web pages, documents, tool output, tickets) concatenated into prompts with no separation or privilege boundary. Look for retrieval content treated as instructions.
- LLM02 Sensitive Information Disclosure: secrets, system data or other users' data in prompts, logs or responses; no output filtering for PII.
- LLM03 Supply Chain: unpinned models, datasets, plugins, MCP servers and SDKs; unverified model artifacts (pickle files); see `supply-chain-security`.
- LLM04 Data and Model Poisoning: unreviewed fine-tuning or RAG ingestion pipelines; write access to knowledge bases.
- LLM05 Improper Output Handling: model output passed to shell, SQL, `eval`, HTML (markdown image or link exfiltration), or URLs without validation.
- LLM06 Excessive Agency: tools with broad permissions, no human approval for destructive actions, shared credentials, agents able to send email, move money or write files unrestricted.
- LLM07 System Prompt Leakage: secrets or access rules placed inside the system prompt; reliance on prompt as access control.
- LLM08 Vector and Embedding Weaknesses: shared vector indexes without tenant filters, no access control on retrieval, embeddings of sensitive data.
- LLM09 Misinformation: relevant where outputs drive decisions; review grounding and human review (security-relevant only when it enables abuse).
- LLM10 Unbounded Consumption: missing token, request and tool-call limits and budgets; review configuration only, no load tests.

## Agent and MCP specifics
Tool schemas without argument validation, tool descriptions from untrusted servers, tool output fed back as instructions, cross-tool data exfiltration chains, missing per-tool authorization on the server side, long-lived tokens in agent configs.

## Data handling
Prompt and response logging with personal data, third-party model provider data retention settings.

## Detail
Per-topic review guidance (what to look at, static vs manual signals, secure behaviour, limitations) is in `docs/methodology/ai-llm.md` (REVIEWED WITH CHANGES - experimental). Additional topics there: trust boundaries, model/artifact supply chain (pickle/safetensors, `trust_remote_code`, unpinned downloads), tool poisoning, RAG poisoning and citation integrity, logging and evaluation.

## Mapping to reviewed checks

Match each category above to executable check IDs in [catalog checks](catalog-checks.md); anything without a reviewed ID is a manual check and stays `planned` or `blocked` until performed with evidence.

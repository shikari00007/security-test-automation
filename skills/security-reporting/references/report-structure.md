# Report structure

1. Header: run id, profile, mode (offline or authorized lab with scope reference), target path, tool versions.
2. Coverage (first): ledger with denominators; blocked and not-applicable counts with reasons.
3. Confirmed findings: id, title, severity with rationale, check id, `path:line`, redacted evidence, expected secure behavior, remediation, regression test link.
4. Needs-validation candidates: what is claimed, what is missing to decide.
5. Rejected candidates: one line with reason (auditable).
6. Untested checks: table check, domain, state, reason, what unblocks it.
7. Limitations: profile limits, tools missing, areas not inspected.
8. Next steps: fixes, manual lab checks needing written scope, retest.

Language: 'no findings from executed checks' is allowed; 'secure' is not. Do not include secrets, tokens, personal or customer data.

# Verdict rules

| Verdict | Requires |
|---|---|
| confirmed | Verifier independently re-read the cited location, found attacker-controlled input or insecure configuration reaching the sink or setting, found no effective mitigation, and the claim matches the evidence. |
| needs_validation | Plausible but unresolved: depends on runtime config, deployment, or a dynamic test needing written scope; or verifier and discoverer disagree; or the verifier could not open the evidence. |
| rejected | Mitigation found, code unreachable or test-only, evidence does not say what was claimed, or duplicate of another finding. Reason required. |

Additional rules:
- Evidence that cannot be re-derived downgrades the verdict.
- Severity is assigned after the verdict, with rationale (impact, exploitability, exposure).
- Scanner output alone is never `confirmed`.
- A confirmed finding then flows to `security-regression-generation` and `security-reporting`.
- Automated CLI re-execution (`security-skills rerun`) confirms the rule still fires; it does not replace the independent verifier.

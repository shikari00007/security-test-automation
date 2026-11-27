# Diff mini-mode: threat-model one PR in about 10 minutes

Use when the question is "does this change open anything?" and a full model is out of proportion. Output is a short PR comment plus, if a threat is real, a row added to `docs/security/threat-model.md`.

## Step 0: decide whether it is needed (1 minute)

Get the changed files with the project's usual diff (`git diff --stat <base>...HEAD`; read-only). It is triggered when the diff touches any of:

| Signal in the diff | Example paths and patterns |
| --- | --- |
| New or changed route, handler, RPC, GraphQL field | `routes/`, `controllers/`, `@app.route`, `router.get(` |
| Auth, session, role or permission code | `auth/`, `middleware/`, `permissions`, `role` |
| New outbound call or third party | `fetch(`, `requests.`, new SDK in manifest |
| New inbound callback, webhook, queue consumer | `webhook`, `consumer`, `subscribe` |
| Storage, upload, bucket, database schema | `migrations/`, `*.tf`, `upload` |
| Personal or sensitive data fields | new columns like `email`, `address`, `token` |
| LLM or agent code | prompt templates, tool definitions, retrieval |
| Infra and deployment boundary | Dockerfile, k8s manifests, network rules |

If none match (copy, styling, internal refactor, tests only): reply "no boundary change; threat model unchanged" and stop. That is a valid outcome.

## Step 1: sketch the delta (2 minutes)

Write the changed flow as 3-8 mermaid lines using the node ids already in `docs/security/threat-model.md` (add new ids for new things). Mark new nodes and flows. Identify which existing flow ids, assets and actors it touches. If no model exists, create only the delta diagram and note "no baseline model; consider a full pass".

## Step 2: ask five questions of each new or changed flow (4 minutes)

1. Who can call or trigger this, and is that checked server-side per object and per tenant? (S, E)
2. What input is trusted that came from outside the boundary, and where is it validated? (T)
3. What sensitive data moves, where does it get stored or logged, who else receives it? (I, LINDDUN)
4. What is unbounded (size, count, time, cost) and can one actor exhaust it? (D)
5. Would we know who did it afterwards? (R) For LLM code add: what untrusted text reaches the model and what can it then do? (LLM01, LLM06)

Write an abuse case for every "I am not sure" or "no" answer, using the template in [stride-linddun-prompts.md](stride-linddun-prompts.md).

## Step 3: rank, mitigate, test (3 minutes)

Score with the [rubric](ranking-and-test-mapping.md), name the concrete mitigation as a suggested diff location, and name the test. Prefer adding the test to this PR. Do not block the PR on Low rows; recommend blocking on High rows that are unmitigated and untested, stated as a recommendation for the reviewers.

## Output: PR comment format

```markdown
### Threat model delta (diff mode)
Scope: <PR title>; baseline: docs/security/threat-model.md (last_reviewed YYYY-MM-DD) | none
Flows touched: F3, F7 (new)

| ID | Abuse case | Risk | Why | Mitigation (where) | Test |
| --- | --- | --- | --- | --- | --- |
| T-0NN | ... | High (6) | ... | ... | ... |

Not analysed: <what you could not see, e.g. infra repo>
Model update: rows T-0NN added | no update needed
Checks run: threat-model linter passed | not run
```

## After the review

- Add the rows to the main table with status `planned` and bump `last_reviewed`; run the linter.
- If the PR changes the architecture picture, update the main diagram in the same PR.
- If a High threat is fixed, hand to `security-regression-generation` to capture a test that fails without the fix.

## Boundaries of this mode

It sees only the diff and the files you open. It does not replace a full model when a new service, role or data class is introduced; say "escalate to full model" in that case.

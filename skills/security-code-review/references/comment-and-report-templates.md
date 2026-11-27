# Comment and report templates

Tone: assume the author is competent and busy. Describe the code, not the person. Explain the why in one or two sentences, give the fix, say how to check it. Do not write "obviously" or "you forgot".

## Inline comment (finding)

```
[<Severity> | confidence <High/Medium/Low> | <Block / Fix before release / Suggestion>]
What: <one sentence: what the code does that is unsafe>
Why it matters: <who can do what to whom; the concrete impact>
Path: <source file:line -> ... -> sink file:line>
Fix: <smallest change; a code snippet if short>
Verify: <test or command that fails before and passes after>
Assumption (if any): <what I could not see, and what would change my mind>
Refs: <CWE-xxx / ASVS x.y.z (5.0.0), optional>
```

Example:

```
[High | confidence High | Block]
What: invoice_detail loads the invoice by id only; owner_id is selected but never compared with the caller.
Why it matters: any logged-in user can read any other customer's invoice by changing the id in the URL.
Path: URL <int:invoice_id> (app.py:36) -> SELECT ... WHERE id = ? (app.py:39-41) -> render_template (app.py:45)
Fix: add "AND owner_id = ?" with the current user's id (404 when no row), or a shared ownership helper.
Verify: add a test where user 2 requests user 1's invoice and asserts 404; it should fail on this commit.
Refs: CWE-639; ASVS 5.0.0 8.2.2
```

## Inline comment (question)

```
Question (non-blocking until answered): Is /internal/export reachable from the public ingress? If so it needs authentication; if it is only reachable from the batch network, a comment saying so would help the next reviewer.
```

## Inline comment (suggestion / hygiene)

```
Suggestion (non-blocking | Hygiene): the log line includes the customer's e-mail. Logs usually have wider access and longer retention than the database. Log the user id instead: app.logger.info("invoice %s viewed by user_id=%s", inv_id, user_id).
```

## Inline comment (checked, no issue)

```
Checked, no change needed: {{ inv.note }} looks like stored XSS, but the template is .html under Flask, which autoescapes, and there is no |safe. I confirmed the rendered output contains &lt;script&gt;. If this template ever becomes .txt or adds |safe, revisit.
```

## Quick review output ("quick review of this PR")

```
Quick security review of <PR/branch> (<N files, M lines>), time-boxed.
Verdict: <Block | Changes requested | Looks OK for security with notes>
Findings (max 5; every finding is a CANDIDATE until security-finding-validation confirms it):
1. [Sev (reason) | Conf (reason) | Block/Suggest] file:line - path: src -> hop -> sink - why (one sentence) - fix (one sentence) - verify (test/command)
Checked and fine: <short list, e.g. query params bound; template autoescape on; auth decorator present>
Not checked: <files skipped, dynamic behaviour, dependencies advisories, deployment config>
Status: static candidates, not independently confirmed.
This is a read-only diff review; it does not show the code is secure.
```

## Review report template (full)

```
# Security review: <title / PR link>
Reviewer: <agent/human>  Date: <date>  Base..Head: <commits>  Context read: <context file, ticket, design note>

## 1. Scope and coverage
- Files reviewed: <n of m>. Not reviewed and why: <generated, binary, vendored>.
- Change types detected: <endpoint, query, template, ...> -> checklists applied.
- Assumptions: <list>
- Checks that could not be done (blocked): <running the app, advisories DB, deployment config>

## 2. Summary
<3 sentences: what the change does, overall risk, recommendation (block / fix before release / approve with suggestions).>

## 3. Findings
| ID | Severity | Confidence | Action | Location | Title |
|---|---|---|---|---|---|
| SR-1 | High | High | Block | app.py:39 | Missing ownership check on invoice detail |

### SR-1 <title>
What / Why it matters / Path / Evidence / Fix / Verify / Refs (template above)
Validation: <not yet | sent to security-finding-validation | verdict>

## 4. Checked and no issue
<each item with the reason, e.g. "template note field: autoescape protects it">

## 5. Hygiene and suggestions (non-blocking)

## 6. Tests reviewed
<which security tests exist; do they assert denial; missing negative tests>

## 7. Open questions for the author

## 8. Limits
Static reading of the diff and the files named above. No dynamic testing. Not a statement that the application is secure.
```

## Review-thread etiquette

- One concern per comment; group duplicates ("same pattern at lines X, Y, Z").
- Offer to pair or to send a patch for non-trivial fixes; do not push to the author's branch without being asked.
- When the author disagrees, ask for the control that protects the path and verify it; update the label rather than defend it.
- When a finding is confirmed, link the fix PR and the regression test back to the thread.

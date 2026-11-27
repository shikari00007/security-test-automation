# Worked example: a small Flask PR with three planted issues

Synthetic invoice service. Files are real and runnable in `worked-example/`:

| Path | What it is |
|---|---|
| `worked-example/before/` | main branch: `GET /invoices` (owner-scoped list) |
| `worked-example/after/` | PR branch: adds `GET /invoices/<id>`, a template and one test |
| `worked-example/pr.diff` | `diff -ruN before after` (this is the PR) |
| `worked-example/verify_claims.py` | executes every claim below, plus the fix |
| `worked-example/verify_py_claims.py`, `verify_js_claims.mjs` | execute the framework claims used in `language-framework-checklists.md` |

PR description (as the author wrote it): "Add invoice detail page so customers can see their note and total. Test included."

## The diff in brief (`after/app.py`)

```python
@app.get("/invoices/<int:invoice_id>")                       # line 36
def invoice_detail(invoice_id):
    user = current_user()                                    # authenticated only
    inv = db().execute(
        "SELECT id, owner_id, total_cents, note FROM invoices WHERE id = ?", (invoice_id,)   # lines 39-41
    ).fetchone()
    if inv is None:
        abort(404)
    app.logger.info("invoice %s viewed by %s (%s)", inv["id"], user["name"], user["email"])  # line 44
    return render_template("invoice.html", inv=inv)          # template prints {{ inv.note }}
```

Plus `templates/invoice.html` (`Customer note: {{ inv.note }}`) and `tests/test_invoice_detail.py` with a single test: the owner gets 200.

## How the review proceeds

1. Orient: new authenticated route, new query, new template, new test. Checklists applied: endpoint, query, template, tests.
2. Boundaries: source `invoice_id` from the URL (attacker-controlled by any logged-in user); sinks: SQL (parameterized), template (stored `note` written by a customer), log (name and e-mail).
3. Trace each path and apply the false-alarm gate.

## Ground truth (planted)

| # | Planted issue | Truth | Verified by |
|---|---|---|---|
| 1 | Detail query has no ownership predicate | Real vulnerability (broken object-level authorization / IDOR, CWE-639), High | `verify_claims.py`: user 2 gets 200 on user 1's invoice |
| 2 | Stored `note` rendered with `{{ inv.note }}` | NOT an issue: Flask autoescape on `.html`, no `|safe` | `verify_claims.py`: `<script>` absent, `&lt;script&gt;` present |
| 3 | E-mail address written to application log | Hygiene (CWE-532), Low/Hygiene | `verify_claims.py`: e-mail present in log record |

Additional observation (a finding, tied to #1): the only test asserts success for the owner; there is no denial test, so the missing check is not caught.

## Ideal review output

```
Security review: "Add invoice detail page" (3 files)
Verdict: BLOCK until SR-1 is fixed. Everything else is non-blocking.

SR-1 [High | confidence High | Block] Any logged-in user can read any customer's invoice
 Where: app.py:39-41 (query), route at app.py:36
 What: invoice_detail looks the invoice up by id only. owner_id is selected but never compared with the
       caller's id, so authentication is checked and authorization is not.
 Why it matters: ids are small integers, so a customer can walk /invoices/1, /2, ... and read other
       customers' totals and notes (CWE-639; ASVS 5.0.0 8.2.2). The list endpoint at app.py:27-33 does scope by
       owner, so the intent is clearly owner-only.
 Path: <int:invoice_id> (app.py:36) -> WHERE id = ? (app.py:39-41) -> render_template (app.py:45) -> response
 Reproduction idea (synthetic data): two users; user 2 requests the id of an invoice owned by user 1;
       expected 404, observed 200 (confirmed in the sandbox with Flask 3.1 test client).
 Fix: "SELECT id, total_cents, note FROM invoices WHERE id = ? AND owner_id = ?", (invoice_id, user["id"]).
       Keep 404 for both "missing" and "not yours" so ids cannot be probed. Better still: put the ownership
       predicate in a shared helper that every invoice query uses.
 Verify: add test_other_user_cannot_read_invoice (user 2 -> 404, body has no total). It must FAIL on this
       commit and pass after the fix. Then run: pytest tests/.
 Next: send the evidence packet to security-finding-validation for independent confirmation, then to
       vulnerability-triage-and-fix for the patch and security-regression-generation for the test.

SR-2 [Hygiene | confidence High | Suggestion, non-blocking] E-mail address in the log line (app.py:44)
 Why: logs are usually readable by more people and kept longer than the database; the e-mail adds PII
       without helping debugging (CWE-532).
 Fix: app.logger.info("invoice %s viewed by user_id=%s", inv["id"], user["id"]).

Tests: tests/test_invoice_detail.py asserts only that the owner gets 200. It would pass with or without the
 ownership check. Suggest the denial test above (this is the test that makes SR-1 stay fixed).

Checked, no change needed:
 - invoice.html prints {{ inv.note }} (customer-controlled, so I checked for stored XSS). Flask autoescapes .html
   templates and there is no |safe, so <script> is rendered as &lt;script&gt; (verified in a sandbox). Not a finding.
   Revisit if the template is renamed to .txt, uses |safe, or note moves into a <script> block or an href.
 - SQL uses a bound parameter for invoice_id; the <int:...> converter also rejects non-integers.
 - Route requires a session (current_user aborts 401).

Not checked: deployment config (session cookie flags, debug), dependency advisories for Flask, rate limiting,
 how note is sanitized on write (not needed for this finding, but relevant if the data is ever exported).
This is a static diff review; it does not show the application is secure.
```

What the ideal output deliberately does NOT do: flag `{{ inv.note }}` as XSS; call the log line "critical"; block on the log line; claim the PR is secure after the fix; paste an exploit.

## Rerunning the verification

```bash
cd skills/security-code-review/references/worked-example
python3 -I verify_claims.py            # needs Flask; prints PASS/FAIL per claim, exit 0 when all hold
python3 -I verify_py_claims.py         # needs Flask, Django, pydantic
(cd after && python3 -m pytest -q -p no:cacheprovider tests)   # the PR's own test: passes (and proves nothing about denial)
mkdir /tmp/jsbox && cd /tmp/jsbox && npm init -y && npm i express react react-dom \
  && cp <repo>/skills/security-code-review/references/worked-example/verify_js_claims.mjs . && node verify_js_claims.mjs
```

Result when this skill was authored (2026-11-25): all `verify_claims.py` checks PASS (7 of 7, including the fix: 404 for user 2, 200 for owner and for own invoice); `verify_py_claims.py` 12 of 12 PASS; `verify_js_claims.mjs` 6 of 6 PASS (Express 5.3.0, React 19.3.1, Node 24). Versions can change behaviour; re-run against your pins.

## Sources checked (primary)

- OWASP ASVS 5.0.0 (May 2025), github.com/OWASP/ASVS tag v5.0.0, `5.0/en/`: requirements 1.2.1, 1.2.2, 1.2.4, 1.3.4-1.3.6, 2.2.1, 3.5.3, 5.2.1-5.2.2, 5.3.1-5.3.2, 8.2.1, 8.2.2, 8.3.1, 11.3.1, 13.3.1, 13.4.2, 15.2.1, 15.2.4, 15.3.1-15.3.3, 16.5.1 read and matched to the wording used in the checklists. ASVS 4.0.3 numbering differs; do not mix editions.
- OWASP Code Review Guide: the project page (owasp.org/projects/code-review-guide) points to the current July 2017 PDF, v2.0. Used as method background only; no section numbers are cited in this skill.
- CWE (cwe.mitre.org, version 5.0 pages): 22, 78, 79, 89, 94, 95, 117, 285, 306, 327, 330, 352, 434, 502, 532, 601, 639, 798, 862, 915, 918, 942, 1333, 1395 fetched and titles confirmed.
- OWASP Top 10 for LLM Applications 2025 (genai.owasp.org): LLM01, LLM02, LLM05, LLM06, LLM07, LLM10 names confirmed.
- Package hallucination: Spracklen et al., "We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs", arXiv 2406.10279 (title and authors confirmed on arxiv.org; accepted at USENIX Security).

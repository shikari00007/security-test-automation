# Verification notes

Date: 2026-11-26. Applies the changes from an independent review, required changes 1-6.

## ASVS 5.0.0 re-check (primary source)

Fetched raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md and 0x20-V11-Cryptography.md on 2026-11-26 and read the requirement text:

| Id | Text (abridged) | Used for |
|---|---|---|
| 3.5.1 | validate that cross-origin requests originate from the app (anti-forgery tokens or extra non-CORS-safelisted headers) when not relying on preflight | CSRF anti-forgery |
| 3.5.2 | if relying on preflight, requests must not be able to skip it | preflight reliance |
| 3.5.3 | sensitive functionality uses POST/PUT/PATCH/DELETE, not safe methods; or strict Sec-Fetch-* validation | method choice |
| 11.3.1 | insecure block modes (ECB) and weak padding (PKCS#1 v1.5) not used | block modes/padding |
| 11.4.1 | only approved hash functions; MD5 disallowed for any cryptographic purpose | MD5/SHA-1 |
| 11.4.2 | passwords stored with an approved computationally intensive KDF | password hashing |
| 11.5.1 | non-guessable values from a CSPRNG with at least 128 bits entropy | randomness |

All replacement citations match their text; no further correction was needed.

## Changes applied

1. change-type-checklists.md: crypto line rewritten (11.3.1, 11.4.1, 11.4.2); ASVS 11.5.1 added to CWE-330 line.
2. change-type-checklists.md: CSRF line cites 3.5.1 and 3.5.3.
3. comment-and-report-templates.md: quick format now has candidate marker, path src -> hop -> sink, severity/confidence with reasons, verify, and a Status line.
4. SKILL.md: description names secure-coding-patterns and security-unit-testing (Not for, plus Related for secure-coding-patterns); "confirming a finding" shortens the clause; description is 1021 characters; "Does not apply" gained the two neighbours.
5. evals: better_skill fixed (secure-coding-patterns, vulnerability-triage-and-fix); 2 security-unit-testing and 1 threat-modeling negatives added. code-review-and-quality and code-simplification remain as real neighbours outside this suite (allowed by the validator unless --strict-better).
6. SKILL.md Verification: throwaway-copy sentence added.

## Template usability check

The revised quick format was applied by hand to a seeded FastAPI diff (/tmp/scr_review2/b.diff, f-string SQL in LIKE and ORDER BY); every field was fillable. Result:

```
Quick security review of b.diff (1 file, 6 lines), time-boxed.
Verdict: Block
Findings (max 5; every finding is a CANDIDATE until security-finding-validation confirms it):
1. [High (authenticated user can read other users' rows via injected OR/UNION) | High (string built into SQL with request params q and sort, no allow-list) | Block] search.py:12 - path: q/sort query params (search.py:10) -> f-string sql (search.py:12) -> con.execute (search.py:13) - values and ORDER BY identifier are concatenated into SQL - bind q as a parameter ('%'||?||'%') and map sort through an allow-list - verify: test that q="zzz' OR owner_id=2 --" returns no other owner's row
Checked and fine: owner_id=? is a bound parameter
Not checked: callers/auth of get_user, DB permissions, other files
Status: static candidates, not independently confirmed.
This is a read-only diff review; it does not show the code is secure.
```

# Rule accuracy (curated corpus)

Measured on `fixtures/accuracy/*/cases.json`: hand-written positive variants and tricky benign negatives per rule.
**These numbers describe the curated corpus only; they are not a field false-positive rate.** Field spot checks: RULE-ACCURACY-FIELD-*.md.Zero FP/FN here holds *by construction*: rules were tuned until every case passed, so this proves regression-safety, not accuracy.

| Rule | Cases | TP | FP | FN | Negatives clean |
|---|---|---|---|---|---|
| SEC-AI-001 | 23 | 9 | 0 | 0 | 14 |
| SEC-AI-002 | 18 | 10 | 0 | 0 | 11 |
| SEC-AI-003 | 24 | 10 | 0 | 0 | 14 |
| SEC-AI-004 | 9 | 4 | 0 | 0 | 5 |
| SEC-AND-001 | 12 | 6 | 0 | 0 | 8 |
| SEC-AND-002 | 8 | 3 | 0 | 0 | 5 |
| SEC-AND-003 | 10 | 4 | 0 | 0 | 6 |
| SEC-AND-004 | 9 | 3 | 0 | 0 | 6 |
| SEC-AND-005 | 8 | 5 | 0 | 0 | 5 |
| SEC-AND-006 | 10 | 6 | 0 | 0 | 6 |
| SEC-API-001 | 9 | 4 | 0 | 0 | 6 |
| SEC-API-002 | 8 | 4 | 0 | 0 | 5 |
| SEC-API-003 | 8 | 3 | 0 | 0 | 5 |
| SEC-API-004 | 10 | 5 | 0 | 0 | 6 |
| SEC-API-005 | 10 | 6 | 0 | 0 | 6 |
| SEC-API-006 | 9 | 8 | 0 | 0 | 5 |
| SEC-DSK-001 | 9 | 6 | 0 | 0 | 6 |
| SEC-DSK-002 | 10 | 4 | 0 | 0 | 7 |
| SEC-DSK-003 | 11 | 6 | 0 | 0 | 6 |
| SEC-DSK-004 | 9 | 4 | 0 | 0 | 5 |
| SEC-DSK-005 | 9 | 5 | 0 | 0 | 5 |
| SEC-IOS-001 | 8 | 3 | 0 | 0 | 5 |
| SEC-IOS-002 | 7 | 3 | 0 | 0 | 4 |
| SEC-IOS-003 | 8 | 4 | 0 | 0 | 5 |
| SEC-IOS-004 | 8 | 6 | 0 | 0 | 5 |
| SEC-K8S-001 | 9 | 5 | 0 | 0 | 6 |
| SEC-K8S-002 | 7 | 5 | 0 | 0 | 4 |
| SEC-K8S-003 | 9 | 5 | 0 | 0 | 6 |
| SEC-K8S-004 | 10 | 7 | 0 | 0 | 7 |
| SEC-K8S-005 | 8 | 3 | 0 | 0 | 5 |
| SEC-K8S-006 | 8 | 5 | 0 | 0 | 5 |
| SEC-SC-001 | 25 | 12 | 0 | 0 | 15 |
| SEC-SC-002 | 10 | 12 | 0 | 0 | 6 |
| SEC-SC-003 | 9 | 4 | 0 | 0 | 6 |
| SEC-SC-004 | 8 | 6 | 0 | 0 | 5 |
| SEC-SC-005 | 9 | 5 | 0 | 0 | 5 |
| SEC-SC-006 | 50 | 28 | 0 | 0 | 30 |
| SEC-SC-008 | 9 | 10 | 0 | 0 | 5 |
| SEC-WEB-001 | 13 | 8 | 0 | 0 | 7 |
| SEC-WEB-002 | 61 | 33 | 0 | 0 | 36 |
| SEC-WEB-003 | 11 | 7 | 0 | 0 | 7 |
| SEC-WEB-004 | 10 | 5 | 0 | 0 | 5 |
| SEC-WEB-005 | 48 | 33 | 0 | 0 | 28 |
| SEC-WEB-006 | 65 | 33 | 0 | 0 | 38 |
| SEC-WEB-007 | 17 | 15 | 0 | 0 | 10 |
| SEC-WEB-008 | 12 | 8 | 0 | 0 | 8 |
| SEC-WEB-009 | 9 | 6 | 0 | 0 | 5 |
| SEC-WEB-010 | 10 | 7 | 0 | 0 | 5 |

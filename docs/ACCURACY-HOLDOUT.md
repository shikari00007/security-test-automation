# Hold-out accuracy evaluation of the reworked Web / Supply-chain rules

This page describes how the rule rework (SEC-SC-001, SEC-SC-006, SEC-WEB-002, SEC-WEB-005, SEC-WEB-006) was measured, because accuracy claims made on the code a rule was tuned on are not trustworthy.

## Method
- **Two fresh hold-out sets of public repositories** (pinned commits below). The rule authors were not allowed to read a hold-out set before it was measured; after measurement the first set was released as training evidence and the second was kept unseen.
- **Precision:** a seeded sample of findings (at most 25 per rule and 8 per repo) from the *realistic* repositories only, labelled by independent reviewers who read the surrounding code and did not know which tool version produced the finding. Labels: `TP` (plausibly exploitable defect), `TP-opt` (the pattern is real but the context is benign, intentional or unexploitable), `FP` (the rule's claim is wrong). *Pattern precision* = (TP + TP-opt) / n; *strict precision* = TP / n.
- **Recall:** an independently built ground truth of known-vulnerable code locations in deliberately vulnerable applications; a location counts as found if the rule reports the same file within two lines of the range.
- The runner caps scanning at 5,000 files per repository root, identically before and after.

## Results on the unseen hold-out (set 2)
| Measure | Before rework | After rework |
|---|---|---|
| Pattern precision, labelled sample | 66% (38 of 58) | 82% (42 of 51) |
| SEC-SC-006 findings across the 12 repositories | 115 | 38 |
| SEC-SC-006 pattern precision | 28% (sample of 25 of 75 findings) | 54% (all 13 findings) |
| SEC-WEB-002 pattern precision | 92% | 88% (no improvement) |
| Strict precision (TP only) | 0% | 0% |
| Recall, 83 known-vulnerable locations | 29% (24) | 42% (35) |
| Recall WEB-002 / WEB-005 / WEB-006 / SC-006 / SC-001 | 8% / 0% / 61% / 33% / 33% | 28% / 36% / 70% / 33% / 33% |
| Recall by language: PHP / Java / Python / TypeScript / JavaScript | 5/17, 10/16, 1/20, 3/17, 3/4 | 14/17, 11/16, 2/20, 3/17, 3/4 |

The first hold-out showed little change after a first tuning round (recall 34% to 32%), which is why a second round was run against a fresh set.

## How to read this
- **No sampled finding in the realistic repositories was shown to be a real exploitable vulnerability** (strict precision 0% in both runs). These rules flag *sinks and patterns*; in mature code most are benign or intentional. Treat every result as a candidate.
- The 51% strict-precision figure in the README comes from an earlier, more liberal labelling of a different sample of the pre-rework rules; the two measurements are **not comparable** and neither supersedes the other.
- **Pattern precision improved mainly through SEC-SC-006.** SEC-WEB-002 did not improve. Samples for SEC-WEB-005 (3), SEC-WEB-006 (5 to 10) and SEC-SC-001 (0) are too small to draw conclusions.
- **Recall remains low overall** and very low for Python (2/20) and TypeScript (3/17). The PHP and Java detectors added in this rework have no benign real-world PHP/Java corpus behind them, so their false-positive rate is unknown.
- Labels come from a reviewer that prefers `TP-opt` when exploitability is uncertain, which depresses strict precision by design.
- Numbers describe these samples, not all code.

## Pinned hold-out repositories
Set 1 (training evidence after measurement): django/djangoproject.com 2e42ee2, gothinkster/django-realworld-example-app 29c9d42, expressjs/express 43fca52, pallets/flask 49943b5, tiangolo/full-stack-fastapi-template 77e550a, nestjs/nest 258e747, gothinkster/node-express-realworld-example-app 30b68e1, spring-projects/spring-petclinic 500158f, frappe/frappe 76e6cb0, NodeBB/NodeBB ace15bc, django/django 9bb0da7, apache/superset 47ac273; vulnerable: appsecco/dvna 9ba473a, digininja/DVWA 502ac15, snoopysecurity/dvws-node 4221c04, OWASP/NodeGoat c5cb68a, adeyosemanputra/pygoat 2aa4cc1.
Set 2 (unseen): getredash/redash f561a53, TryGhost/Ghost e6e3a5b, netbox-community/netbox ddcb3ce, wagtail/wagtail 9d1d10e, zulip/zulip b700599, directus/directus 4856582; vulnerable: juice-shop/juice-shop c9f9922, WebGoat/WebGoat 4e98f1c, anxolerd/dvpwa 4a8f4a4, we45/Vulnerable-Flask-App b6a4f97, stamparm/DSVW 9ca3c9a, OWASP/Vulnerable-Web-Application c0f2689.
These repositories were read statically and never executed. Per-change details and recall risks: `docs/RULE-ACCURACY-FIELD-*.md`.

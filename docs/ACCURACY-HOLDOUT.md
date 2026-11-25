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

---
# Hold-out set 3: the full rework (both rounds) against the original rules

The complete rework (round 1 plus the PHP/Java precision, Python and TypeScript/JavaScript taint detection and SEC-SC-006 generalisation of round 2) was measured on a third set of 23 public repositories that none of the rule authors had read. **"Before" is the original pre-rework rule set (the code of the first public release line), so the table shows the cumulative effect of both rounds, not the second round alone.** 13 realistic PHP, Java, Python and TypeScript projects for precision and 10 deliberately vulnerable apps for recall (73 independently identified known-vulnerable locations). Method as above; the sample was 108 findings before and 105 after (31 of the "after" labels reused from identical "before" findings).

| Measure | Before | After |
|---|---|---|
| Pattern precision, labelled sample | 81% (87 of 108) | 91% (96 of 105) |
| SEC-SC-006 pattern precision | 32% (8 of 25) | 76% (19 of 25); findings on the realistic repos 163 to 33 |
| SEC-WEB-002 pattern precision | 84% | 92% |
| Strict precision (TP only) | 0% | 0% |
| Recall, 73 known-vulnerable locations | 34% (25) | 45% (33) |
| Recall WEB-002 / WEB-005 / WEB-006 / SC-006 / SC-001 | 6% / 8% / 83% / 42% / 0% | 29% / 31% / 94% / 37% / 0% |
| Recall by language: PHP / Java / JavaScript / Python | 7/16, 6/14, 3/8, 6/28 | 11/16, 6/14, 5/8, 8/28 |

Reading: SEC-SC-006 precision and PHP/JavaScript recall improved. **Python recall barely generalised** (the Python detectors recovered 18 of 19 known locations on the repositories used to build them, but only 8 of 28 on the unseen set), Java recall did not change, SEC-SC-001 recall stayed at zero, SEC-SC-006 recall dipped by one location, and no sampled finding in realistic code was shown to be exploitable. WEB-005 (21 findings) and SC-001 samples are small.

Set 3 repositories (pinned commits). Realistic: ansible/ansible cd313f0, symfony/demo f42980c, excalidraw/excalidraw 5681e7d, laravel/framework 321caf7, jenkinsci/jenkins 3209f9a, keycloak/keycloak 549623e1, matomo-org/matomo 53047c4, mitmproxy/mitmproxy 0466185, n8n-io/n8n afd87867, outline/outline 8e7b1fa, spring-projects/spring-boot ebb5e11c, sqlalchemy/sqlalchemy 9c88919, WordPress/WordPress 0761560. Vulnerable: dolevf/Damn-Vulnerable-GraphQL-Application a961308, snyk-labs/nodejs-goof add14ba, Audi-1/sqli-labs e96f217, payatu/Tiredful-API 0134124, erev0s/VAmPI f16052d, SasanLabs/VulnerableApp c44987a, Contrast-Security-OSS/vulnpy b81885e, fportantier/vulpy 5249cc8, OWASP/wrongsecrets 692b475, s4n7h0/xvwa fb30fa5.

---
# Hold-out set 4 (OWASP Benchmark and hand-curated apps): recall gained, false positives on benign look-alikes rose

A fourth set (14 repositories: realistic Python/Java projects, five hand-curated vulnerable apps, and the OWASP Benchmark for Java and Python) adds a direct false-positive measure: the Benchmark marks each test case as really vulnerable or as a designed benign look-alike (260 vulnerable and 210 benign locations were scored; hand-curated entries are all vulnerable).

| Measure (rules SEC-WEB-002/005/006 and SEC-SC-006) | Original rules | This pull request's rules |
|---|---|---|
| Recall of known-vulnerable locations | 19% (50 of 260) | 33% (85 of 260) |
| Benign look-alikes wrongly flagged | 15% (31 of 210) | 27% (56 of 210) |
| ...Java SQL (SEC-WEB-006) | 78% (31 of 40) | 90% (36 of 40) |
| ...Python command injection (SEC-WEB-005) | 0% (0 of 40) | 40% (16 of 40) |
| Recall, OWASP Benchmark Python / Java | 1/69, 34/119 | 14/69, 49/119 |

So the rework found more of the vulnerable code, but it also **flags more of the deliberately benign cases**, most of all in Java SQL and Python command execution. The Benchmark is a synthetic worst case for pattern-based tools (its flows are routed through helper methods and dead branches), so these figures are not a prediction for ordinary code, but the direction is a real cost. Pattern precision on the realistic repositories of this set was 90% (53 of 59 sampled findings genuine patterns) for the original rules; it was not re-sampled for the new rules.


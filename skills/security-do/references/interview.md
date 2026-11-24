# Configuration interview

Ask only what the request left open. Offer the default and accept short answers.

| # | Question | Options | Default |
|---|---|---|---|
| 1 | Application type | auto, web, api, android, ios, desktop, supply-chain (cloud-kubernetes and ai-llm when detected or requested) | auto |
| 2 | Profile | quick (high-confidence static, PR), standard (full static, manual items listed untested), deep (adds dynamic/manual items as blocked until authorized) | standard |
| 3 | Path | local directory | current directory |
| 4 | Mode | static offline, or authorized dynamic in lab/staging | static offline |
| 5 | Independent verification | on / off | on |
| 6 | Regression tests | propose / none (never applied without approval) | propose |
| 7 | Report formats | sarif, json, junit, markdown | sarif,json,markdown |
| 8 | Environment and authorization scope | only asked when mode is dynamic: environment, explicit targets, authorized_by, expiry, isolation, test accounts | none |
| 9 | CI gate | fail-on severity (never/info/low/medium/high/critical), strict (gate on unverified candidates) | high |

If question 4 is dynamic, stop until all scope elements are answered. Production is refused outright.

Echo the final configuration back as one block and wait for a yes.

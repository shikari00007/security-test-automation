# Formats

| Format | Use | Notes |
|---|---|---|
| Markdown | humans | coverage first |
| JSON | tooling, retest | includes run metadata, executions, findings, verification records |
| SARIF 2.1.0 | code scanning UIs | `ruleId` = check id; locations `path` and `startLine`; keep verdict in result properties |
| JUnit XML | CI test tabs | failed = confirmed or gated finding; blocked/not applicable as skipped, not passed |

Rules: never encode `blocked` as pass; keep redaction in every format; stable ids so reruns diff cleanly.

Without the CLI, hand-write Markdown and JSON; SARIF and JUnit are optional and can be produced later from the JSON.

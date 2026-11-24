# Orchestration

| Step | Skill | CLI equivalent |
|---|---|---|
| Detect | `security-start` | `security-skills detect <path>` |
| Context | `security-project-context` | none (conversation) |
| Plan | `security-test-strategy` | `security-skills plan <path> --type T --profile P` |
| Run domain checks | domain skills | `security-skills audit <path> --type T --profile P --report sarif,json,markdown` |
| Dynamic (authorized only) | domain skills' dynamic references | add `--mode lab --scope scope.json` |
| Validate | `security-finding-validation` | `security-skills verify <results.json> --target <path> --findings` and `rerun` |
| Coverage | `security-coverage-analysis` | `security-skills coverage <results.json>` |
| Regression | `security-regression-generation` | `security-skills regression generate --results <results.json> --finding <ID>` |
| Report | `security-reporting` | reports written by `audit` to `--output-dir` |

Canonical command: `security-skills audit ./app --type auto --profile standard --report sarif,json,markdown`.

Exit handling: a non-zero CI exit means the gate tripped, not that the tool crashed; read the report. Missing optional tools surface as `blocked` checks, which you must carry into the final summary.

Delegating: when subagents are available, give each domain skill a bounded task (path, profile, no network) and merge their ledgers; keep verification in a separate fresh-context agent.

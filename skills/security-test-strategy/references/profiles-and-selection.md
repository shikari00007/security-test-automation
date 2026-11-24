# Profiles and selection

| Profile | Use | Includes | Excludes |
|---|---|---|---|
| quick | coding, PR | high-confidence static/config checks for detected domains, bounded time | manual and dynamic checks (listed as deferred) |
| standard | before merge | all static checks for applicable domains, dependency and config review; manual/dynamic listed untested | active testing |
| deep | pre-release, security review | standard plus every reviewed dynamic/hybrid/manual check, planned but `blocked` until authorization | nothing is auto-run without written scope |

Applicability decision: a check applies when its file globs match something in the project and its required facts hold (for example `two_test_identities`). Otherwise `not_applicable` with the unmet condition written out.

Catalog lookup on demand (do not paste the catalog): `security-skills catalog checks <domain>` lists reviewed executable checks; `security-skills catalog list --domain D --category C --limit N` browses the larger normalized catalog. Without the CLI, use each domain skill's `references/methodology.md`.

Plan output fields: domain, check id, state, reason, required tool, required access, profile tag.

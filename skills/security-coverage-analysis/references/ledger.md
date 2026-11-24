# Coverage ledger

| Measure | Definition |
|---|---|
| catalog | reviewed checks available for the domains |
| selected | checks in the profile for applicable domains |
| not_applicable | selected checks whose preconditions are absent (reason required) |
| deferred | outside profile |
| blocked | applicable but missing tool, scope, account or device (reason required) |
| executed | actually ran; has tool output |
| pass / fail / inconclusive | outcomes of executed checks only |
| verified | findings with `confirmed` verdict |
| unverified | candidates `needs_validation` |
| rejected | candidates rejected with reasoning |

Arithmetic: executed + blocked + planned = applicable; applicable + not_applicable + deferred = selected. If the sums do not close, the run is not reportable.

Wording rules:
- Say 'N of M applicable checks executed', never 'secure' or 'no vulnerabilities'.
- List blocked reasons with counts and what would unblock each.
- A pass covers only what the check examines; name the limit.

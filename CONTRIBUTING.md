# Contributing

- New automated checks need: reviewed metadata (`security_runner/data/checks/<domain>.json`), a registered rule, and a `fixtures/<name>/{vulnerable,secure}` pair with `expected.json`. Tests must prove no false positive on the secure variant.
- Never add exploit payloads or active-attack automation. Dynamic checks stay `executor: none` until a policy-gated, isolated adapter and review exist.
- Third-party text/code: record license and pinned revision in `docs/THIRD-PARTY.md` first.
- Run `python -m pytest -q` and `security-skills skills validate skills` before opening a PR.

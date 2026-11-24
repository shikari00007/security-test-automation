# Frameworks

| Framework | Support via CLI | Notes |
|---|---|---|
| pytest | executable | static/file-level and unit assertions run offline |
| Playwright | skeleton only | needs a running lab app and written scope; developer completes selectors and login |
| Schemathesis | skeleton only | property tests from OpenAPI; run against lab, never production; do not enable heavy fuzzing without approval |
| JUnit | manual | Android/JVM: assert manifest or config values via instrumentation-free unit tests where possible |
| XCTest | manual | iOS: parse Info.plist/entitlements in a unit test; UI tests need a simulator |
| Espresso | manual | Android UI/intent tests on an emulator, lab only |

Guidance for manual frameworks: prefer tests that read build artifacts (manifest, plist, config) because they are fast and offline; use UI tests only when behavior is runtime-only. Name tests `test_<FINDING-ID>_<behavior>`. Keep fixtures synthetic.

CLI: `security-skills regression generate --results results.json --finding FIND-001 --framework pytest --output-dir ./security-regression`.

# Field accuracy check: SEC-WEB / SEC-API / SEC-SC static rules

Scope: rules SEC-WEB-001..010, SEC-API-001..006, SEC-SC-001,002,003,004,005,006,008, run over real third-party code available on this machine. Companion to the adversarial corpus in `fixtures/accuracy/web-api-sc/cases.json`.

## Method

* Trees scanned (each capped at 5000 files per scanned root; large trees were scanned as one root per top-level directory so the cap never truncated a project): `/usr/lib/python3/dist-packages` (1317 package dirs, 43,361 files), `/usr/share/nodejs` + `/usr/lib/code-oss` + `/opt/Insomnia` + `/opt/MQTTX` (31,332 files), `~/Tools` (security tools and payload repos, 1,175 files), `~/.cargo/registry/src` (347 Rust crates incl. their `.github/workflows`, 14,167 files).
* `python3 -m security_runner audit <tree> --type web|api|supply-chain --no-verify --fail-on never` was exercised end to end on `~/Tools/cve-search`; the bulk passes used the same rule functions through `ScanContext` so every observation could be dumped with its source line.
* Up to 25 findings per rule were sampled (seeded) from the triage run and read in context (3 lines). Verdicts: **TP** = the rule's defect is really there and plausibly exploitable or a genuine policy violation; **TP-opt** = the pattern is correct and present, but the context is benign or intentional (opt-in insecure flag, protocol-mandated primitive, code generator, library repository where a lockfile is optional, dev tooling); **FP** = the rule is wrong (not the defect). Strict precision = TP / sampled; pattern precision = (TP + TP-opt) / sampled.
* Findings in `fixtures`, test dirs and minified files were included in the raw counts when the rule at triage time did not already exclude them, so the raw counts are a pessimistic view.

## Totals

`Raw initial` = first field pass before any field-driven fix; `Raw triage` = the pass that was sampled below; `Raw final` = after the fixes listed in the next section (final code).

| Rule | Raw initial | Raw triage | Raw final | Sampled | TP | TP-opt | FP | Strict precision | Pattern precision |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SEC-API-004 | 4 | 3 | 3 | 3 | 1 | 1 | 1 | 33% | 67% |
| SEC-API-005 | 1 | 0 | 0 | 0 | - | - | - | n/a | n/a |
| SEC-SC-001 | 1295 | 25 | 25 | 25 | 1 | 24 | 0 | 4% | 100% |
| SEC-SC-002 | 597 | 449 | 449 | 25 | 25 | 0 | 0 | 100% | 100% |
| SEC-SC-003 | 7 | 6 | 6 | 6 | 3 | 3 | 0 | 50% | 100% |
| SEC-SC-004 | 803 | 803 | 803 | 25 | 25 | 0 | 0 | 100% | 100% |
| SEC-SC-005 | 170 | 170 | 170 | 25 | 25 | 0 | 0 | 100% | 100% |
| SEC-SC-006 | 211 | 59 | 39 | 25 | 5 | 0 | 20 | 20% | 20% |
| SEC-SC-008 | 24 | 24 | 24 | 24 | 24 | 0 | 0 | 100% | 100% |
| SEC-WEB-001 | 6 | 4 | 4 | 4 | 2 | 2 | 0 | 50% | 100% |
| SEC-WEB-002 | 64 | 50 | 41 | 25 | 1 | 15 | 9 | 4% | 64% |
| SEC-WEB-003 | 4 | 1 | 1 | 1 | 1 | 0 | 0 | 100% | 100% |
| SEC-WEB-005 | 438 | 100 | 100 | 25 | 2 | 19 | 4 | 8% | 84% |
| SEC-WEB-006 | 50 | 29 | 29 | 25 | 8 | 12 | 5 | 32% | 80% |
| SEC-WEB-007 | 142 | 103 | 103 | 25 | 11 | 11 | 3 | 44% | 88% |
| SEC-WEB-008 | 63 | 20 | 20 | 19 | 10 | 8 | 1 | 53% | 95% |
| **All sampled** | | | | 282 | 144 | 95 | 43 | 51% | 85% |

Rules with no findings in any scanned tree: SEC-WEB-004, SEC-WEB-009, SEC-WEB-010, SEC-API-001, SEC-API-002, SEC-API-003, SEC-API-006 (no CORS/redirect/CSRF application code, OpenAPI specs or request-bound model code exist in these trees; the Burp config hit for SEC-API-005 was a false positive and was fixed). Their accuracy rests on the adversarial corpus only; no field precision claim is made for them.

Caveat on SEC-SC-001/002/004/005/008: the sampled trees are installed packages and vendored crates, so these supply-chain findings are real policy violations (floating specs, tag-pinned actions, missing `permissions:`) but not necessarily risk for a downstream consumer.

## Fixes driven by the field pass

* Minified/bundled JS (average line > 200 chars or any line > 1500 chars) is blanked before matching: removed hundreds of findings (WEB-002/005/006/008 and SC-006 in VS Code bundles, html5shiv).
* `*.d.ts` skipped; `function eval(` / `def exec(` definitions are not calls (WEB-005).
* WEB-005: Python/JS `eval`/`exec` only reported when the argument is dynamically built or visibly request/user derived (taint words) instead of any non-literal; first-argument literals (`exec('import x', ns)`) and test paths are excluded; `exec`/`cp.exec` look only at the first argument (callback bodies no longer count); constant concatenations (`'a' + 'b'`) are static.
* WEB-006: SELECT must look like SQL (column list), Title-case prose ("Delete from ...") is not SQL, `%`-operator needs a space (`LIKE '%_X'` no longer matches), constant `${VERSION}`/`{TABLE}` and table-identifier interpolation or `quote_name(...)` are not flagged, test paths skipped; added multi-line concatenation and PHP `. $var`.
* WEB-007: skip test/conftest paths; comparisons, dict keys, typed defaults and `# nosec`/`noqa: S323` lines; `rejectUnauthorized` as ternary else-branch or member read; `verify=False` only in TLS-related files; opt-out branches (`if cfg.ignore_certs:`); raw docstrings are now blanked.
* WEB-008: word-based token detection (`author`, `sessionStorage`, camelCase) instead of substrings; `session` only as session_id/key/token; dropped `nonce` and `reset`; `usedforsecurity=False`, `# nosec`, `noqa: S324` honoured; hash window no longer looks at the previous line.
* WEB-003: config classes named Dev/Test/Debug/Local, multi-line `app.run(..., debug=True)` support, module-level `DEBUG = True` only in web-looking files, Cargo `debug = true` ignored.
* WEB-001: `cookiejar.set_cookie(make_session_cookie(x))` (first argument a call) is not an HTTP cookie; `document.cookie ==` comparisons ignored.
* WEB-002: literal-only multi-line concatenation, ternary of two literals, read-modify-write of the element's own markup, `.insertAdjacentHTML()` text inside strings, and `trusted*`/`safe*` names are not flagged; multi-line `el.innerHTML =\n value` now handled.
* WEB-004/010: allowlist-checking origin callbacks are not wildcard; CSRF disabled only in test files or Test/Dev config classes is ignored.
* API-002: pagination/cursor `token` query parameters; API-003: single-label (compose/cluster) and `.internal` hosts count as local; API-004: `alg = "none"` inside a string literal is ignored; API-005: key must not be a suffix of a longer name (`perform_graphql_introspection`), env-gated lines (`NODE_ENV`, `isDev`) and test paths skipped; API-006: built-in constructors (`new Error(req.body)`) excluded.
* SC-001: published libraries (`main`/`exports`/`files`/`keywords`/...), library crates, gemspec Gemfiles and composer libraries are not required to ship a lockfile; SC-002: local-path requirements (`-e .`) and prose files named requirements*.txt skipped; SC-003: well-known tool-only hooks (`husky install ...`, `patch-package`, `prisma generate`, `node-gyp rebuild`) skipped; SC-008: loopback http indexes allowed.
* SC-006: placeholders/templates (`%s`, `%(x)s`, `{...}`), GUIDs, UPPER_SNAKE names, hyphenated words, timestamps, plain URLs, bare words/type names, lowercase-only keywords straddling camelCase (`kSecReturn`), library file names, bcrypt/argon hashes, values with whitespace; example/usage lines, comment and docstring text in code files, documentation files (LICENSE/NOTICE/ThirdPartyNotices), test/testdata/SelfTest paths (private keys and provider tokens in tests: only tokens still reported), PEM headers without a key body, documentation sample keys.

## Triage tables (sampled findings)


### SEC-API-004  (sampled 3 of 3)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `py:nxc/modules/wam.py:59` | TP | jwt.decode with verify_signature False |
| 2 | `py:oauthlib/common.py:221` | FP | audience heuristic on a generic helper that takes no audience |
| 3 | `py:redis/auth/token.py:89` | TP-opt | decodes only to read the expiry claim |

### SEC-SC-001  (sampled 25 of 25)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `node:package.json:1` | TP | private application manifest with dependencies and no lockfile |
| 2 | `node:@babel/preset-modules/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 3 | `node:@npmcli/mock-globals/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 4 | `node:@npmcli/mock-registry/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 5 | `node:@npmcli/smoke-tests/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 6 | `node:@tapjs/docs/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 7 | `node:@tapjs/dummy-plugin/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 8 | `node:acorn-bigint/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 9 | `node:acorn-class-fields/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 10 | `node:acorn-export-ns-from/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 11 | `node:acorn-import-meta/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 12 | `node:acorn-jsx/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 13 | `node:acorn-private-class-elements/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 14 | `node:acorn-static-class-features/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 15 | `node:css-loader/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 16 | `node:envinfo/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 17 | `node:indexes-of/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 18 | `node:json-buffer/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 19 | `node:lodash/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 20 | `node:prismjs/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 21 | `node:process-on-spawn/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 22 | `node:schema-utils/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 23 | `node:spdx-ranges/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 24 | `node:yaml-types/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |
| 25 | `node:yaml/package.json:1` | TP-opt | published library repository; lockfile policy is optional (library heuristic now covers files/keywords/main) |

### SEC-SC-002  (sampled 25 of 449)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `tools:cve-search/requirements.txt:7` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 2 | `tools:cve-search/requirements.txt:22` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 3 | `node:@types/cacheable-request/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 4 | `node:@types/estraverse/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 5 | `node:@types/lodash.camelcase/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 6 | `node:@types/lodash.clamp/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 7 | `node:@types/lodash.drop/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 8 | `node:@types/lodash.initial/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 9 | `node:@types/lodash.inrange/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 10 | `node:@types/lodash.intersectionwith/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 11 | `node:@types/lodash.lte/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 12 | `node:@types/lodash.maxby/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 13 | `node:@types/lodash.merge/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 14 | `node:@types/lodash.remove/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 15 | `node:@types/lodash.replace/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 16 | `node:@types/lodash.sumby/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 17 | `node:@types/lodash.throttle/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 18 | `node:@types/lodash.wrap/package.json:28` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 19 | `node:@types/n3/package.json:48` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 20 | `node:@types/opener/package.json:23` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 21 | `node:base64-js/package.json:14` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 22 | `node:internal-slot/package.json:61` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 23 | `node:interpret/package.json:30` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 24 | `node:move-concurrently/package.json:19` | TP | wildcard/range/dist-tag/git-branch or bare requirement |
| 25 | `node:qrcode-terminal/package.json:32` | TP | wildcard/range/dist-tag/git-branch or bare requirement |

### SEC-SC-003  (sampled 6 of 6)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `node:extensions/package.json:10` | TP | project's own postinstall script |
| 2 | `node:package.json:18` | TP | project's own preinstall script |
| 3 | `node:package.json:19` | TP | project's own postinstall script |
| 4 | `node:core-js-pure/package.json:72` | TP-opt | banner-printing postinstall, benign |
| 5 | `node:core-js/package.json:69` | TP-opt | banner-printing postinstall, benign |
| 6 | `node:es5-ext/package.json:116` | TP-opt | banner-printing postinstall, benign |

### SEC-SC-004  (sampled 25 of 803)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `cargo:anyhow-1.0.104/.github/workflows/ci.yml:89` | TP | action pinned to tag/branch, not a full commit SHA |
| 2 | `cargo:bit-set-0.8.0/.github/workflows/rust.yml:49` | TP | action pinned to tag/branch, not a full commit SHA |
| 3 | `cargo:bitflags-1.3.2/.github/workflows/rust.yml:45` | TP | action pinned to tag/branch, not a full commit SHA |
| 4 | `cargo:cssparser-0.37.0/.github/workflows/main.yml:30` | TP | action pinned to tag/branch, not a full commit SHA |
| 5 | `cargo:dtoa-1.0.11/.github/workflows/ci.yml:60` | TP | action pinned to tag/branch, not a full commit SHA |
| 6 | `cargo:field-offset-0.3.6/.github/workflows/publish.yml:22` | TP | action pinned to tag/branch, not a full commit SHA |
| 7 | `cargo:indexmap-1.9.3/.github/workflows/ci.yml:92` | TP | action pinned to tag/branch, not a full commit SHA |
| 8 | `cargo:indexmap-2.14.2/.github/workflows/ci.yml:42` | TP | action pinned to tag/branch, not a full commit SHA |
| 9 | `cargo:indexmap-2.14.2/.github/workflows/ci.yml:97` | TP | action pinned to tag/branch, not a full commit SHA |
| 10 | `cargo:jsonptr-0.7.1/.github/workflows/check.yml:119` | TP | action pinned to tag/branch, not a full commit SHA |
| 11 | `cargo:jsonptr-0.7.1/.github/workflows/scheduled.yml:50` | TP | action pinned to tag/branch, not a full commit SHA |
| 12 | `cargo:jsonptr-0.7.1/.github/workflows/test.yml:139` | TP | action pinned to tag/branch, not a full commit SHA |
| 13 | `cargo:proc-macro2-1.0.107/.github/workflows/ci.yml:111` | TP | action pinned to tag/branch, not a full commit SHA |
| 14 | `cargo:proc-macro2-1.0.107/.github/workflows/ci.yml:146` | TP | action pinned to tag/branch, not a full commit SHA |
| 15 | `cargo:rustc_version-0.4.1/.github/workflows/rust.yml:37` | TP | action pinned to tag/branch, not a full commit SHA |
| 16 | `cargo:semver-1.0.28/.github/workflows/ci.yml:31` | TP | action pinned to tag/branch, not a full commit SHA |
| 17 | `cargo:serde-untagged-0.1.9/.github/workflows/ci.yml:89` | TP | action pinned to tag/branch, not a full commit SHA |
| 18 | `cargo:simd-adler32-0.3.10/.github/workflows/build.yaml:28` | TP | action pinned to tag/branch, not a full commit SHA |
| 19 | `cargo:string_cache-0.8.9/.github/workflows/ci.yml:30` | TP | action pinned to tag/branch, not a full commit SHA |
| 20 | `cargo:string_cache-0.9.0/.github/workflows/ci.yml:30` | TP | action pinned to tag/branch, not a full commit SHA |
| 21 | `cargo:thiserror-1.0.69/.github/workflows/ci.yml:70` | TP | action pinned to tag/branch, not a full commit SHA |
| 22 | `cargo:unicode-ident-1.0.27/.github/workflows/ci.yml:50` | TP | action pinned to tag/branch, not a full commit SHA |
| 23 | `cargo:unicode-ident-1.0.27/.github/workflows/ci.yml:98` | TP | action pinned to tag/branch, not a full commit SHA |
| 24 | `cargo:unicode-ident-1.0.27/.github/workflows/ci.yml:108` | TP | action pinned to tag/branch, not a full commit SHA |
| 25 | `cargo:zmij-1.0.23/.github/workflows/ci.yml:102` | TP | action pinned to tag/branch, not a full commit SHA |

### SEC-SC-005  (sampled 25 of 170)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `cargo:bit-set-0.8.0/.github/workflows/rust.yml:24` | TP | job has no permissions block and no workflow-level permissions |
| 2 | `cargo:bit-vec-0.8.0/.github/workflows/rust.yml:13` | TP | job has no permissions block and no workflow-level permissions |
| 3 | `cargo:bitflags-1.3.2/.github/workflows/rust.yml:37` | TP | job has no permissions block and no workflow-level permissions |
| 4 | `cargo:cfg-expr-0.15.8/.github/workflows/ci.yml:13` | TP | job has no permissions block and no workflow-level permissions |
| 5 | `cargo:cfg-expr-0.15.8/.github/workflows/ci.yml:52` | TP | job has no permissions block and no workflow-level permissions |
| 6 | `cargo:cssparser-0.29.6/.github/workflows/main.yml:51` | TP | job has no permissions block and no workflow-level permissions |
| 7 | `cargo:embed-resource-3.0.12/.github/workflows/msvc.yml:10` | TP | job has no permissions block and no workflow-level permissions |
| 8 | `cargo:field-offset-0.3.6/.github/workflows/toolchain.yml:83` | TP | job has no permissions block and no workflow-level permissions |
| 9 | `cargo:http-1.5.0/.github/workflows/ci.yml:26` | TP | job has no permissions block and no workflow-level permissions |
| 10 | `cargo:http-1.5.0/.github/workflows/ci.yml:72` | TP | job has no permissions block and no workflow-level permissions |
| 11 | `cargo:ico-0.6.0/.github/workflows/tests.yml:40` | TP | job has no permissions block and no workflow-level permissions |
| 12 | `cargo:json-patch-3.0.1/.github/workflows/main.yml:12` | TP | job has no permissions block and no workflow-level permissions |
| 13 | `cargo:keyboard-types-0.7.0/.github/workflows/ci.yml:6` | TP | job has no permissions block and no workflow-level permissions |
| 14 | `cargo:keyboard-types-0.8.3/.github/workflows/ci.yml:6` | TP | job has no permissions block and no workflow-level permissions |
| 15 | `cargo:keyboard-types-0.8.3/.github/workflows/ci.yml:40` | TP | job has no permissions block and no workflow-level permissions |
| 16 | `cargo:libappindicator-0.9.0/.github/workflows/covector-version-or-publish.ym:9` | TP | job has no permissions block and no workflow-level permissions |
| 17 | `cargo:parking_lot-0.12.5/.github/workflows/rust.yml:60` | TP | job has no permissions block and no workflow-level permissions |
| 18 | `cargo:pkg-config-0.3.34/.github/workflows/ci.yml:14` | TP | job has no permissions block and no workflow-level permissions |
| 19 | `cargo:shlex-2.0.1/.github/workflows/test.yml:33` | TP | job has no permissions block and no workflow-level permissions |
| 20 | `cargo:simd-adler32-0.3.10/.github/workflows/build.yaml:40` | TP | job has no permissions block and no workflow-level permissions |
| 21 | `cargo:string_cache-0.8.9/.github/workflows/ci.yml:17` | TP | job has no permissions block and no workflow-level permissions |
| 22 | `cargo:target-lexicon-0.12.16/.github/workflows/main.yml:10` | TP | job has no permissions block and no workflow-level permissions |
| 23 | `cargo:tauri-winres-0.3.7/.github/workflows/ci.yml:9` | TP | job has no permissions block and no workflow-level permissions |
| 24 | `cargo:tendril-0.4.3/.github/workflows/main.yml:10` | TP | job has no permissions block and no workflow-level permissions |
| 25 | `cargo:version_check-0.9.5/.github/workflows/ci.yml:9` | TP | job has no permissions block and no workflow-level permissions |

### SEC-SC-006  (sampled 25 of 59)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `tools:cve-search/etc/configuration.ini:13` | TP | database password committed in configuration.ini |
| 2 | `py:aardwolf/connection.py:1288` | FP | demo credential inside __main__ test snippet |
| 3 | `py:aardwolf/examples/scanners/__main__.py:46` | FP | usage example in CLI help |
| 4 | `py:aiosmb/connection.py:1564` | FP | demo credential in __main__ |
| 5 | `py:aiosmb/dcerpc/v5/interfaces/bkrp.py:115` | FP | demo credential in __main__ |
| 6 | `py:aiosmb/examples/epmtest.py:65` | FP | example script test lab credential |
| 7 | `py:asysocks/unicomm/common/scanner/scanner.py:150` | FP | demo credential in a commented-style scanner example |
| 8 | `py:binwalk/plugins/pgp.py:23` | TP | PGP private key block committed |
| 9 | `py:botocore/data/iam/2010-05-08/examples-1.json:1155` | FP | timestamp value under a key containing 'Password' (now fixed) |
| 10 | `py:botocore/data/iam/2010-05-08/examples-1.json:1163` | FP | timestamp value (now fixed) |
| 11 | `py:botocore/data/iam/2010-05-08/examples-1.json:1472` | FP | documentation sample inside botocore examples JSON |
| 12 | `py:botocore/data/sts/2011-06-15/service-2.json:128` | FP | long documentation prose matched mid-string (now skipped) |
| 13 | `py:cryptography/hazmat/primitives/serialization/ssh.py:78` | FP | header constant for a parser, no key body (now fixed) |
| 14 | `py:impacket/krb5/kpasswd.py:49` | FP | service principal name constant (now fixed) |
| 15 | `py:ldeep-1.0.89.dist-info/METADATA:363` | FP | timestamp in documentation (now fixed) |
| 16 | `py:minikerberos/common/factory.py:34` | FP | docstring example hash |
| 17 | `py:nxc/data/default.pem:1` | TP | private key committed (default.pem) |
| 18 | `py:nxc/data/nxc.conf:22` | TP | default password in nxc.conf |
| 19 | `py:nxc/data/nxc.conf:27` | TP | default password in nxc.conf |
| 20 | `py:playwright/driver/package/lib/server/registry/nativeDeps.js:189` | FP | shared-library file name used as a key (now fixed) |
| 21 | `py:spnego/_tls_struct.py:783` | FP | hyphenated identifier value (now fixed) |
| 22 | `py:tornado/auth.py:984` | FP | plain OAuth URL constant (now fixed) |
| 23 | `py:twisted/conch/ssh/keys.py:395` | FP | docstring describing key format (now fixed) |
| 24 | `py:twisted/conch/ssh/keys.py:1511` | FP | header used to build a key string (now fixed) |
| 25 | `py:wapitiCore/parsers/html_parser.py:75` | FP | scanner form-fill default value |

### SEC-SC-008  (sampled 24 of 24)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `tools:cve-search/requirements.txt:24` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 2 | `node:extensions/emmet/package.json:485` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 3 | `node:@isaacs/ts-node-temp-fork-for-pr-2009/package.json:120` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 4 | `node:@isaacs/ts-node-temp-fork-for-pr-2009/package.json:121` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 5 | `node:@isaacs/ts-node-temp-fork-for-pr-2009/package.json:122` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 6 | `node:@isaacs/ts-node-temp-fork-for-pr-2009/package.json:150` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 7 | `node:acorn-bigint/package.json:30` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 8 | `node:acorn-class-fields/package.json:30` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 9 | `node:acorn-export-ns-from/package.json:30` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 10 | `node:acorn-import-assertions/package.json:32` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 11 | `node:acorn-import-attributes/package.json:32` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 12 | `node:acorn-import-meta/package.json:30` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 13 | `node:acorn-numeric-separator/package.json:35` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 14 | `node:acorn-private-methods/package.json:37` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 15 | `node:acorn-static-class-features/package.json:30` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 16 | `node:enhanced-resolve/package.json:78` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 17 | `node:eslint-utils/package.json:30` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 18 | `node:globby/package.json:75` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 19 | `node:interpret/package.json:30` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 20 | `node:micromatch/package.json:48` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 21 | `node:mustache/package.json:54` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 22 | `node:socks-proxy-agent/package.json:126` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 23 | `node:webpack-sources/package.json:57` | TP | dependency fetched from VCS/URL (even when commit-pinned) |
| 24 | `node:webpack/package.json:202` | TP | dependency fetched from VCS/URL (even when commit-pinned) |

### SEC-WEB-001  (sampled 4 of 4)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `py:django/conf/global_settings.py:495` | TP-opt | Django's own default settings module (overridable default) |
| 2 | `py:flask/app.py:194` | TP-opt | Flask default config dict |
| 3 | `py:flask_mongoengine/sessions.py:97` | TP | set_cookie without secure/samesite |
| 4 | `py:tornado/auth.py:443` | TP | set_cookie for token without flags |

### SEC-WEB-002  (sampled 25 of 50)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `cargo:wry-0.53.5/examples/custom_protocol/index.html:22` | FP | key name appended; not attacker-controlled markup |
| 2 | `tools:pentesting-payloads/File uploads/Malicious/XSS-stored/OOB XSS-cookieSt:1` | TP | intentional cookie-stealing XSS payload (exact sink) |
| 3 | `node:extensions/notebook-renderers/src/index.ts:232` | TP-opt | renderer output guarded by an indexOf('<a') check |
| 4 | `node:extensions/notebook-renderers/src/linkify.ts:93` | TP-opt | createHtml helper output |
| 5 | `node:extensions/theme-seti/icons/preview.html:93` | TP-opt | developer preview page |
| 6 | `py:matplotlib/backends/web_backend/js/mpl.js:415` | TP-opt | export format names from backend |
| 7 | `py:mercurial/templates/static/mercurial.js:407` | TP-opt | parsed into a detached document |
| 8 | `py:mercurial/templates/static/mercurial.js:412` | TP-opt | template formatter output |
| 9 | `py:mkdocs/contrib/search/templates/search/main.js:44` | TP-opt | site-owner search index content |
| 10 | `py:mkdocs/themes/mkdocs/js/base.js:49` | FP | static key-name map lookup |
| 11 | `py:playwright/driver/package/lib/server/frames.js:773` | TP-opt | browser automation writes captured HTML |
| 12 | `node:caniuse-lite/data/features/insertadjacenthtml.js:1` | FP | string inside a data file that mentions insertAdjacentHTML() (now fixed) |
| 13 | `node:eslint/lib/cli-engine/formatters/html-template-page.html:107` | FP | element re-derives its own markup (now fixed) |
| 14 | `node:html5shiv/src/html5shiv.js:71` | TP-opt | document CSS text |
| 15 | `node:istanbul-reports/lib/html/assets/sorter.js:69` | FP | own markup plus literal (now fixed) |
| 16 | `node:lodash/perf/asset/perf-ui.js:39` | FP | multi-line literal-only concatenation (now fixed) |
| 17 | `node:lodash/perf/asset/perf-ui.js:47` | FP | multi-line literal-only concatenation (now fixed) |
| 18 | `node:lodash/perf/index.html:44` | TP-opt | path derived from page query in a perf harness |
| 19 | `node:prismjs/components/prism-core.js:590` | TP-opt | highlighter hook output |
| 20 | `node:prismjs/plugins/normalize-whitespace/prism-normalize-whitespace.js:224` | TP-opt | normalizer output |
| 21 | `node:prismjs/plugins/previewers/prism-previewers.js:349` | FP | multi-line literal-only concatenation (now fixed) |
| 22 | `node:prismjs/plugins/previewers/prism-previewers.js:416` | FP | multi-line literal-only concatenation (now fixed) |
| 23 | `node:react-dom/umd/react-dom.development.js:2534` | TP-opt | React's own setInnerHTML implementation |
| 24 | `node:react-dom/umd/react-dom.development.js:2545` | TP-opt | React's own setInnerHTML implementation |
| 25 | `node:react-dom/umd/react-dom.development.js:9338` | TP-opt | React feature-detection scratch element |

### SEC-WEB-003  (sampled 1 of 1)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `tools:cve-search/etc/configuration.ini:24` | TP | Debug: True in deployed configuration.ini |

### SEC-WEB-005  (sampled 25 of 100)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `tools:frida-scripts/rsenet_FriList/01_Observer/Network/NSURL/ios-nsurlreques:45` | TP-opt | eval of a string built from Frida script params; not attacker input |
| 2 | `tools:frida-scripts/rsenet_FriList/02_SecurityBypass/ios-change-system-versi:17` | TP-opt | same Frida pattern |
| 3 | `py:IPython/core/hooks.py:82` | TP | shell=True with editor/filename interpolated |
| 4 | `py:django/core/management/commands/shell.py:127` | TP-opt | django shell command executes stdin by design |
| 5 | `py:mako/codegen.py:117` | TP-opt | mako evals template-author attributes |
| 6 | `py:mako/codegen.py:118` | TP-opt | mako evals template-author attributes |
| 7 | `py:numpy/f2py/auxfuncs.py:632` | TP-opt | f2py build-time eval of generated expression |
| 8 | `py:numpy/f2py/auxfuncs.py:640` | TP-opt | f2py build-time eval of generated expression |
| 9 | `py:ply/cpp.py:609` | TP-opt | ply C-preprocessor evaluates source expression |
| 10 | `py:ply/lex.py:1043` | TP-opt | module name from the library's own package |
| 11 | `py:reportbug/submit.py:432` | TP | mail addresses interpolated into a shell command |
| 12 | `py:scapy/arch/unix.py:83` | TP-opt | configured ifconfig path in shell string |
| 13 | `py:scapy/utils.py:1058` | TP-opt | configured program path |
| 14 | `py:scapy/volatile.py:1368` | TP-opt | fuzzing value object evaluates its own expression |
| 15 | `py:speechd_config/config.py:513` | TP-opt | config-derived path in rm -rf |
| 16 | `py:sqlalchemy/util/typing.py:274` | TP-opt | typing annotation strings |
| 17 | `py:sympy/polys/ring_series.py:2011` | FP | eval of a lookup in a fixed internal dict; matched on the word 'expr' |
| 18 | `py:sympy/utilities/lambdify.py:163` | FP | internal import command string; matched on the word 'command' |
| 19 | `py:twisted/conch/insults/insults.py:1049` | FP | builds names from a constant list; no external input |
| 20 | `node:ajv/lib/compile/jtd/parse.ts:69` | TP-opt | ajv code generation via new Function |
| 21 | `node:es-abstract/operations/getOps.js:195` | TP-opt | dev script exec with local path |
| 22 | `node:es5-ext/function/_define-length.js:39` | TP-opt | es5-ext code generation |
| 23 | `node:tapable/lib/HookCodeFactory.js:31` | TP-opt | tapable code generation |
| 24 | `node:tapable/lib/HookCodeFactory.js:71` | TP-opt | tapable code generation |
| 25 | `node:webpack/lib/EvalSourceMapDevToolPlugin.js:217` | FP | string template that emits the text 'eval(' into generated code; not a call |

### SEC-WEB-006  (sampled 25 of 29)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `py:django/db/backends/oracle/introspection.py:177` | FP | table/column pass through quote_name (on following line) |
| 2 | `py:django/db/models/sql/compiler.py:592` | FP | wraps an already-compiled SQL fragment |
| 3 | `py:nltk/sem/chat80.py:435` | TP-opt | internal table-name identifier |
| 4 | `py:nxc/modules/hash_spider.py:94` | TP | username concatenated into LIKE |
| 5 | `py:nxc/modules/hash_spider.py:120` | TP | username concatenated into LIKE |
| 6 | `py:nxc/modules/hash_spider.py:124` | TP | username concatenated into LIKE |
| 7 | `py:nxc/modules/hash_spider.py:191` | TP | username in f-string UPDATE |
| 8 | `py:nxc/modules/hash_spider.py:239` | TP | pc name in f-string SELECT |
| 9 | `py:nxc/modules/hash_spider.py:250` | TP | pc name concatenated |
| 10 | `py:nxc/modules/mssql_coerce.py:58` | TP-opt | operator-supplied listener in SQL sent to target (pentest tool) |
| 11 | `py:nxc/modules/mssql_coerce.py:59` | TP-opt | as above |
| 12 | `py:nxc/modules/mssql_coerce.py:67` | TP-opt | as above |
| 13 | `py:nxc/modules/mssql_coerce.py:68` | TP-opt | as above |
| 14 | `py:nxc/modules/mssql_coerce.py:69` | TP-opt | as above |
| 15 | `py:nxc/modules/mssql_coerce.py:70` | TP-opt | as above |
| 16 | `py:nxc/modules/mssql_coerce.py:71` | TP-opt | as above |
| 17 | `py:nxc/modules/mssql_priv.py:276` | FP | constant SQL appended to a context prefix |
| 18 | `py:nxc/modules/teams_localdb.py:44` | TP | name concatenated into SELECT |
| 19 | `py:nxc/protocols/mssql/mssqlexec.py:98` | TP-opt | operator-supplied path in OPENROWSET |
| 20 | `py:nxc/protocols/wmi/wmiexec_event.py:159` | FP | WQL query with an internal numeric id, not SQL |
| 21 | `py:setuptools/_vendor/typing_extensions.py:2105` | FP | docstring example of what NOT to do (docstring now blanked) |
| 22 | `py:sqlalchemy/dialects/sqlite/base.py:2279` | TP-opt | dialect-quoted identifiers |
| 23 | `py:zenmapCore/UmitDB.py:151` | TP-opt | internal table-name identifier |
| 24 | `py:zenmapCore/UmitDB.py:246` | TP | id formatted into WHERE |
| 25 | `py:zim/notebook/index/pages.py:829` | TP-opt | internal fragment appended to ORDER BY |

### SEC-WEB-007  (sampled 25 of 103)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `py:aiohttp/connector.py:883` | TP-opt | aiohttp ssl=False opt-out |
| 2 | `py:asyauth/protocols/credssp/client/native.py:22` | TP | CredSSP client disables verification unconditionally |
| 3 | `py:asysocks/intercepting/server.py:64` | TP | intercepting proxy disables upstream verification |
| 4 | `py:asysocks/unicomm/common/unissl.py:132` | TP-opt | inside an option branch |
| 5 | `py:asysocks/unicomm/protocol/quic.py:99` | TP | QUIC client verify_mode none |
| 6 | `py:bloodhound_ce/ad/authentication.py:118` | TP | ldap3 Tls(validate=CERT_NONE) unconditional |
| 7 | `py:certipy/commands/relay.py:102` | TP | verify=False on HTTP request |
| 8 | `py:certipy/lib/req.py:1109` | TP | verify=False on HTTP request |
| 9 | `py:dns/query.py:1205` | TP-opt | only when no server_hostname |
| 10 | `py:mercurial/debugcommands.py:3775` | TP-opt | debug command |
| 11 | `py:mercurial/sslutil.py:234` | TP-opt | set from --insecure style config |
| 12 | `py:mercurial/sslutil.py:323` | FP | hostname is verified manually in _verifycert immediately after |
| 13 | `py:nxc/modules/ldap-checker.py:128` | TP | check_hostname disabled unconditionally in tool |
| 14 | `py:nxc/protocols/winrm.py:104` | TP | requests.post(verify=False) |
| 15 | `py:pip/_vendor/urllib3/contrib/pyopenssl.py:434` | FP | class-attribute defaults of a pyOpenSSL compatibility shim |
| 16 | `py:pip/_vendor/urllib3/util/ssl_.py:141` | FP | SSLContext compatibility shim defaults |
| 17 | `py:playwright/driver/package/bin/reinstall_msedge_beta_mac.sh:6` | TP | curl -k in installer script |
| 18 | `py:redis/connection.py:1076` | TP-opt | None maps to CERT_NONE by documented option |
| 19 | `py:scapy/layers/http.py:803` | TP-opt | else branch of a verify flag |
| 20 | `py:scapy/layers/ldap.py:1808` | TP-opt | else branch of a verify flag |
| 21 | `py:spnego/tls.py:89` | TP | CredSSP TLS disables verification unconditionally |
| 22 | `py:tornado/simple_httpclient.py:469` | TP-opt | only when validate_cert is False |
| 23 | `py:urllib3/connection.py:945` | TP-opt | only when verification disabled by caller |
| 24 | `py:urllib3/util/ssl_.py:359` | TP-opt | honours caller's cert_reqs |
| 25 | `py:wapitiCore/attack/mod_ssl.py:78` | TP | scanner connects without verification |

### SEC-WEB-008  (sampled 19 of 20)

| # | Location (tree:path:line) | Verdict | Reason |
|---:|---|---|---|
| 1 | `tools:cve-search/web/api.py:64` | TP | Flask SECRET_KEY from random.getrandbits |
| 2 | `py:django/contrib/auth/hashers.py:651` | TP-opt | Django legacy SHA1 hasher kept for compatibility |
| 3 | `py:django/contrib/auth/hashers.py:753` | TP-opt | Django legacy unsalted SHA1 hasher |
| 4 | `py:impacket/examples/ldap_shell.py:153` | TP | random.choice for a generated account password |
| 5 | `py:impacket/examples/ldap_shell.py:319` | TP | same |
| 6 | `py:impacket/examples/ntlmrelayx/attacks/ldapattack.py:157` | TP | same |
| 7 | `py:impacket/examples/ntlmrelayx/attacks/ldapattack.py:211` | TP | same |
| 8 | `py:impacket/examples/ntlmrelayx/attacks/ldapattack.py:322` | TP | PFX password from random.choice |
| 9 | `py:impacket/examples/ntlmrelayx/attacks/smbattack.py:136` | TP | computer-account password from random.choice |
| 10 | `py:impacket/ntlm.py:698` | TP | session key from random.choice |
| 11 | `py:mitmproxy/utils/htpasswd.py:77` | TP-opt | htpasswd {SHA} verification format |
| 12 | `py:msldap/client.py:1443` | TP | random.choice password |
| 13 | `py:nxc/modules/remove-mic.py:175` | TP | session key from random.choice |
| 14 | `py:oscrypto/_asymmetric.py:738` | TP-opt | OpenSSL EVP_BytesToKey md5 mandated by PEM format |
| 15 | `py:oscrypto/_asymmetric.py:740` | TP-opt | as above |
| 16 | `py:oscrypto/asymmetric.py:444` | TP-opt | as above |
| 17 | `py:oscrypto/asymmetric.py:446` | TP-opt | as above |
| 18 | `py:sleekxmpp/plugins/xep_0078/legacyauth.py:115` | TP-opt | XEP-0078 legacy digest mandated by protocol |
| 19 | `py:wadllib/application.py:803` | FP | multipart boundary, not a secret |

## Known limitations (not fixed, deliberately)

* SEC-WEB-005 / 006 / 007 / 008 remain pattern-level: in libraries and security tooling most remaining hits are TP-opt (intentional opt-outs, code generators, protocol-mandated MD5/SHA-1, operator-supplied SQL in pentest tools). Without data-flow analysis these cannot be separated from real defects; expect lower precision on library code than on application code.
* SEC-API-004 keeps the 'verified without audience' heuristic because the shipped fixtures require it; it is noisy on generic helpers that legitimately leave audience validation to the caller.
* SEC-SC-006 still reports credential-looking literals in demo `__main__` blocks and scanner example payloads; AWS's documented `AKIAIOSFODNN7EXAMPLE` key is flagged in ordinary source paths because the shipped fixture expects it (it is exempted only under docs/examples/tests paths).
* SEC-SC-001 library detection is heuristic; an application manifest that has `main` or `files` and no `start` script is missed. SEC-SC-008 reports commit-pinned git dependencies, as its description states.
* SEC-WEB-009 only follows one hop of tainted variables and misses `redirect(x or '/')`; SEC-WEB-006 misses multi-line SQL where SELECT and FROM are on different lines; SEC-WEB-002 treats any non-literal assignment as unsanitized, including values from static maps.
* SEC-WEB-001 does not evaluate framework defaults inherited from config objects and reports the framework's own default settings modules (TP-opt).

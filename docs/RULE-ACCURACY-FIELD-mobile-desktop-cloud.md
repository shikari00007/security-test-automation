# Field accuracy check: Android, iOS, desktop (Electron/.NET), cloud/Kubernetes rules

Rules covered: SEC-AND-001..006, SEC-IOS-001..004, SEC-DSK-001..005, SEC-K8S-001..006.
Companion to the adversarial corpus `fixtures/accuracy/mobile-desktop-cloud/cases.json`
(187 cases: >=3 positive and >=4 negative per rule, exact `[file, line]` expectations).

## Method and honest caveats

* Samples: nothing relevant exists on this machine (a bounded search of /usr, /opt and the home
  directory found no AndroidManifest.xml, Info.plist, *.entitlements, Dockerfile, *.tf or electron-builder
  config). All samples are therefore shallow `git clone --depth 1` checkouts from GitHub into `/tmp/field-all`,
  used as read-only static input (never built or executed; `.git` removed; large binaries deleted):
  * Android: android/architecture-samples, android/sunflower, android/nowinandroid, OWASP MASTG-Hacking-Playground
    (intentionally vulnerable), dineshshetty/Android-InsecureBankv2 (intentionally vulnerable)
  * iOS: Ranchero-Software/NetNewsWire, nalexn/clean-architecture-swiftui, prateek147/DVIA-v2 and OWASP/iGoat-Swift
    (intentionally vulnerable; only source/plist/entitlement files kept)
  * Electron: electron/electron-quick-start, electron-react-boilerplate, marktext/marktext, doyensec/electronegativity
  * .NET desktop: ShareX/ShareX
  * Kubernetes: kubernetes/examples, GoogleCloudPlatform/microservices-demo, prometheus-operator/kube-prometheus
  * Terraform: bridgecrewio/terragoat (intentionally vulnerable), terraform-aws-modules s3-bucket and security-group
  * Dockerfiles: nginxinc/docker-nginx, jenkinsci/docker (plus those inside the repos above)
* Each domain was audited with `python3 -m security_runner audit <dir> --type <domain> --output-dir /tmp/acc-x
  --fail-on never --no-verify` (all completed, 0 confirmed - static matches are candidates by design). Triage was done
  by calling the registered rules directly on the same trees and reading the code around every hit.
* "TP" means the pattern the rule names is really there. It does NOT mean exploitable: many sample hits are in
  archived/example manifests or are deliberate (NetNewsWire needs plain-HTTP feeds, node-exporter needs hostNetwork).
  Verdict "TP (by definition)" marks those.
* The false-positive fixes below were derived from this same sample, so the post-fix precision is optimistic, and
  the sample is biased toward intentionally vulnerable apps and example repos. Treat it as a sanity check, not a benchmark.
* Recall cannot be measured from this sample: for several rules there was no real positive at all (stated per rule).

## Totals

| | hits triaged | TP | FP |
|---|---|---|---|
| Before fixes | 184 | 162 | 22 |
| After fixes | 162 | 162 | 0 |

Observed precision before fixes 162/184 = 88%; after fixes 162/162 on this sample.
Systematic false positives found and fixed (all now have corpus regression cases):

| Rule | FP class | n | Fix |
|---|---|---|---|
| SEC-AND-003 | "allowBackup not set" reported on library/flavor-overlay manifests (attr-less `<application>`) | 5 | only flag an unset attribute when the manifest defines the app (icon/label/name attr or launcher) |
| SEC-AND-006 | `import static ...MODE_WORLD_READABLE;` counted as a use | 1 | import/package lines ignored |
| SEC-DSK-002 | `shell.openExternal` guarded by a named URL regex (`URL_REG.test`) | 1 | named URL-regex guards recognised |
| SEC-K8S-001 | `hostPath` property inside a CustomResourceDefinition schema; kind-cluster config | 5 | CRD / Cluster / policy kinds treated as inert |
| SEC-K8S-003 | Dockerfiles under `tests/` (test fixture images) | 9 | test-path Dockerfiles skipped |
| SEC-K8S-004 | bucket encrypted by a separate SSE resource referencing it inside a ternary (`aws_s3_bucket.this[0].id`) | 1 | SSE target extraction parses any `bucket =` expression |

Real bugs found by the adversarial corpus (not by field data): `setAllowUniversalAccessFromFileURLs` and the iOS
`allowUniversalAccessFromFileURLs` key were never matched (regex had `Universal` in the wrong place); the shared
`strip_hash` swallowed newlines and shifted line numbers (fixed, plus unit test and regression cases); `strip_c`
treated the tail of `file:///x` as a `//` comment; flow-style YAML (`{privileged: true}`, `data: {k: v}`, inline
`roleRef`), multi-line Terraform CIDR lists, `--- # comment` document separators, Kotlin `ObjectInputStream(`
(no `new`), Kotlin `edit { putString(..) }`, SOPS/empty Secrets, distroless `:nonroot` images, and SSE resources whose
`bucket` attribute follows the nested `rule {}` block.

## SEC-AND-001 exported component without permission

| Location | Verdict | Reason |
|---|---|---|
| InsecureBankv2/app/src/main/AndroidManifest.xml:49 (PostLogin), :58 (DoTransfer), :63 (ViewStatement), :69 (provider), :75 (receiver), :84 (ChangePassword) | TP x6 | exported=true, no permission, intentionally vulnerable app (the provider and receiver are the textbook leaks) |
| InsecureBankv2/wip-attackercode/SniffIntents/.../AndroidManifest.xml:19 | TP | exported receiver with custom action (PoC attacker app) |
| nowinandroid, sunflower, architecture-samples, MASTG manifests | 0 hits | consistent with their `exported="false"`/launcher-only manifests; no misses found by reading them |

7/7 TP. Not modelled: an exported component guarded only by an application-level permission (reported; manual check).

## SEC-AND-002 debuggable

0 hits on all samples. No real `android:debuggable="true"` sample was available (modern templates omit it), so
neither precision nor recall is field-measured; corpus only.

## SEC-AND-003 allowBackup

| Location | Verdict | Reason |
|---|---|---|
| nowinandroid app-nia-catalog:20, app:33; sunflower app:26 | TP | explicit `allowBackup="true"` (sample apps) |
| MASTG-Android-Java-App:13 | TP | explicit true |
| InsecureBankv2 app:25, ExploitAES:6, SniffIntents:6 | TP x3 | explicit true |
| nowinandroid app/src/prod:19, feature/settings/impl:18, core/screenshot-testing:23, sync/work/src/prod:19, ui-test-hilt-manifest:19 | FP x5 (fixed) | overlay/library manifests; the app module's manifest decides |

## SEC-AND-004 cleartext traffic

MASTG-Android-Kotlin-App manifest:14 `usesCleartextTraffic="true"`: TP. No real network-security-config sample with a
cleartext domain-config existed; NSC handling (debug-overrides, loopback-only domains) is corpus-only.

## SEC-AND-005 WebView

MASTG InsecureWebViewActivity.kt:24 (`allowFileAccessFromFileURLs = true`) and :33 (`addJavascriptInterface`),
OMTG_ENV_005_WebView_Local.java:36 and :40, OMTG_ENV_005_WebView_Remote.java:46: 5/5 TP (Kotlin and Java styles).
Other samples: 0 hits. Known miss: JS enabled in one file and the bridge registered in another is not correlated.

## SEC-AND-006 insecure storage

| Location | Verdict | Reason |
|---|---|---|
| MASTG Kotlin MainActivity.kt:77 `putString("auth_token", token)` | TP | plaintext token in prefs |
| MASTG OMTG_DATAST_001_SharedPreferences.java:24 `putString("password", ...)` | TP | plaintext password |
| InsecureBankv2 DoLogin.java:195 (`superSecurePassword`), MyBroadCastReceiver.java:29 (`MODE_WORLD_READABLE`) | TP x2 | |
| MASTG OMTG_DATAST_001_SharedPreferences.java:8 `import static ...MODE_WORLD_READABLE` | FP (fixed) | an import is not a use |

## SEC-IOS-001 ATS disabled

NetNewsWire Mac/Resources/Info.plist:57 and iOS/Resources/Info.plist:66 (TP by definition: RSS feeds over HTTP is a
deliberate trade-off), DVIA-v2 Info.plist:39 (TP), iGoat-Swift Info.plist:38 (TP). A binary `Info.plist` inside a
third-party framework yields an inconclusive note, not a finding. 4/4 TP.

## SEC-IOS-002 get-task-allow

No `.entitlements` file with the key in any sample (none in DVIA-v2/iGoat as shipped); 0 hits, no field evidence.
Behavior change: files whose name contains "debug" are skipped (Xcode debug entitlements legitimately set it).

## SEC-IOS-003 Keychain Always / UserDefaults secrets

0 hits on all samples. I did not verify whether the intentionally vulnerable apps (DVIA-v2, iGoat) store secrets in
ways this rule cannot see (e.g. key names held in constants), so a recall gap is possible but unmeasured. No field positive.

## SEC-IOS-004 UIWebView / file-access prefs

DVIA-v2 ClientSideInjectionDetailViewController.swift:21; iGoat HTMLViewController.swift:5, HintVC.swift:50 and :51,
CrossSiteScriptingExerciseVC.swift:4: 5/5 TP (real UIWebView use). No `allowFileAccessFromFileURLs` sample.

## SEC-DSK-001 Electron webPreferences

0 hits on electron-quick-start, electron-react-boilerplate and marktext (all use secure or default prefs).
No insecure real sample was found, so precision/recall are corpus-only.

## SEC-DSK-002 openExternal / loadURL

| Location | Verdict | Reason |
|---|---|---|
| electron-react-boilerplate src/main/main.ts:90 `shell.openExternal(edata.url)` | TP | window-open handler forwards any scheme |
| marktext ipc/shell.ts:10 and :18 | TP x2 | IPC handler opens renderer-supplied URL unvalidated |
| marktext menu/actions/file.ts:392 | FP (fixed) | guarded by `URL_REG.test(urlCandidate)` |

Known limitation: "validated" is a file-level heuristic (any validation idiom in the file silences the file).

## SEC-DSK-003 auto-update, SEC-DSK-004 connection strings, SEC-DSK-005 deserialization

0 hits on every sample (ShareX has no `BinaryFormatter` deserialization, no connection string with a password, and
no Electron updater). No real positives were available for any of the three: corpus-only.
Behavior changes: package.json is parsed (only `build.publish[].url` counts, not repository/bugs URLs); `.NET` formatters
are flagged only when the file also deserializes; Kotlin `ObjectInputStream(` is now detected; appsettings JSON
`"...Password": "literal"` keys are now detected.

## SEC-K8S-001 privileged / host namespaces / hostPath (56 hits after fixes; first 20 and a sweep of the remainder read)

| Location | Verdict | Reason |
|---|---|---|
| examples/_archived/elasticsearch/es-rc.yaml:21 | TP | `privileged: true` |
| examples/_archived/newrelic-infrastructure/newrelic-infra-daemonset.yaml:18,19,20,26,48,51,54,57 | TP x8 | hostPID/hostIPC/hostNetwork/privileged/hostPath (deliberate agent, by definition) |
| examples/_archived/newrelic/newrelic-daemonset.yaml:21,22,23,29,53,56,60,63 | TP x8 | same |
| examples/_archived/podsecuritypolicy/rbac/pod_priv.yaml:14 | TP | privileged pod demo |
| examples/AI/model-serving-tensorflow/pv.yaml:11 | TP (by definition) | hostPath PersistentVolume |
| vitess controllers (flow style `hostPath: {path: ...}`) | TP | flow-style, found by the added flow matcher |
| sysdig daemonset/rc, flexvolume ds, nfs server | TP | privileged / hostPID / hostPath |
| kube-prometheus nodeExporter-daemonset.yaml:100,101,113,116 | TP (by definition) | node-exporter needs host namespaces; not a vulnerability by itself |
| kube-prometheus tests/e2e/kind/kube-router.yaml:74,108,118-130 | TP | privileged CNI in a CI cluster |
| kube-prometheus setup/*CustomResourceDefinition.yaml (4) | FP (fixed) | `hostPath` is an openAPI schema property |
| kube-prometheus tests/e2e/kind/config.yml:9 | FP (fixed) | kind cluster config, not a workload |

## SEC-K8S-002 run as root

0 hits (kubernetes/examples, microservices-demo, kube-prometheus). No field positive.

## SEC-K8S-003 Dockerfile

* docker-nginx (16 files, e.g. mainline/alpine/Dockerfile:6, debian/Dockerfile:6, modules/Dockerfile:72): TP, final stage has no
  USER (official nginx master runs as root by design, TP by definition).
* kubernetes/examples (28): TP, e.g. `FROM nginx` untagged (https-nginx:15), `ubuntu:14.04` (phabricator:15),
  `curl https://install.meteor.com/ | sh` (meteor/dockerbase:20), scratch without USER (explorer:15).
* microservices-demo (12 hits): TP at the image level (no USER in adservice, currencyservice, emailservice, paymentservice,
  ...; untagged `gcr.io/distroless/static` in checkoutservice:33, frontend:32); the Kubernetes manifests add
  `runAsNonRoot`, which mitigates this outside the Dockerfile.
* terragoat resources/Dockerfile:1: TP.
* jenkinsci/docker `tests/**/Dockerfile` (9): FP (fixed), test fixture images.

## SEC-K8S-004 Terraform

| Location | Verdict | Reason |
|---|---|---|
| terragoat aws/ec2.tf:95 | TP | SSH ingress from `0.0.0.0/0` (multi-line cidr list; was a recall gap before the fix) |
| terragoat alicloud/bucket.tf:7 | TP | `acl = "public-read-write"` |
| terragoat aws/s3.tf:1, 42, 65, 89 and ec2.tf:271 | TP (by definition) | no explicit SSE configuration; AWS now encrypts with SSE-S3 by default, so this is hygiene |
| terraform-aws-s3-bucket main.tf:77 | FP (fixed) | SSE resource references `aws_s3_bucket.this[0].id` inside a conditional |

Because of the SSE default, the title/expected behavior of the check were reworded to "without an explicit server-side
encryption configuration". Terraform variables (`from_port = var.port`) and modules are not resolved (known miss).

## SEC-K8S-005 plaintext Secret

14/14 TP by definition: ten sample Secrets in kubernetes/examples carry base64 demo credentials (e.g.
volumes/iscsi/chap-secret.yaml:7, kube-prometheus examples/basic-auth/secrets.yaml:5 with `# toor` / `# admin`
in the comments), and four kube-prometheus generated Secrets (alertmanager-secret.yaml:12, grafana-config.yaml:11,
grafana-dashboardDatasources.yaml:11) hold plaintext config of low sensitivity (TP, low impact).

## SEC-K8S-006 RBAC wildcards / cluster-admin

prometheus-adapter.yaml:54 and :56, prometheusAdapter-clusterRoleServerResources.yaml:14 and :16: `resources: '*'`
and `verbs: '*'` scoped to `custom.metrics.k8s.io` / `metrics.k8s.io`. TP by definition, low practical risk
(read-mostly metrics API groups). Confidence lowered high -> medium. No cluster-admin binding in the samples.

## Metadata adjusted

SEC-AND-003 high -> medium (app-manifest heuristic); SEC-K8S-001 high -> medium (hostPath/host namespaces are often
deliberate); SEC-K8S-006 high -> medium; SEC-K8S-004 title and expected-secure-behavior reworded (SSE default).

## Known limitations (recorded, not fixed)

* AND: application-level `android:permission` is not modelled; JS-enabled and JS-bridge in different files are not correlated;
  `putString(KEY_CONSTANT, ...)` and multi-line `putString(\n"password"` are missed.
* IOS: `UserDefaults` keys held in constants are missed; `get-task-allow` in non-Debug-named files of debug configs
  is still reported.
* DSK: openExternal validation is file-level; template-literal URLs are treated as unvalidated; `appsettings.Development.json`
  with `Password=` for localhost is still reported (hardcoded credential, even if local).
* K8S: Helm `values.yaml` defaults are not examined and Helm conditional/loop bodies are skipped, so opt-in `hostNetwork: true`
  inside `{{ if }}` is not reported; Kustomize `secretGenerator literals` are not parsed; Terraform variables/modules are not resolved;
  `resources: ["*"]` with read-only verbs is still reported; a Dockerfile `curl ... \` line continuation before `| sh` is missed.

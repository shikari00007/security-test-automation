# GitHub Actions: copy-ready workflows

Four workflows. All third-party actions are pinned to full commit SHAs resolved through the GitHub API on 2026-11-25 (tag in the trailing comment). Before copying: re-resolve if the tag has moved, read the release notes, and let Dependabot (`package-ecosystem: github-actions`) propose bumps. Action names, inputs and versions are checked in [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md). The YAML below parsed with `yaml.safe_load` and passed `actionlint` v1.7.12 with `shellcheck` (so `run:` scripts were linted) and `yamllint`. Fork-PR behaviour of the reusable osv workflow, CodeQL and dependency-review comments is reasoned from the action sources, not observed on a runner.

Trim before use: delete jobs for languages or artifacts the repo does not have (`sca`, `iac-container` and the CodeQL matrix already self-skip on missing files where noted), keep `security-gate` listing exactly the jobs you keep.

## 1. `pr-security.yml` (every pull request)

Design points worth keeping when you edit:

- Trigger is `pull_request`, never `pull_request_target`; fork PRs run with a read-only token and no secrets, which is why SARIF uploads are skipped for forks.
- Top-level `permissions: {}`, then least privilege per job. Only jobs that upload SARIF get `security-events: write`.
- `actions/checkout` with `persist-credentials: false`; `fetch-depth: 0` only where history is needed (gitleaks range, semgrep baseline).
- PR metadata reaches shell only through `env:` (never inline `${{ }}` in `run:`).
- gitleaks is installed as a checksum-verified binary: `gitleaks/gitleaks-action` v3.0.0 needs a `GITLEAKS_LICENSE` secret for organization-owned repos (its README), the CLI does not.
- `pip-audit` has no severity filter (any known vulnerability fails); use `--ignore-vuln ID` with an owner and expiry in your suppression file. `npm audit --audit-level=high` filters by severity.
- semgrep gate reads the severity from the rule (`defaultConfiguration.level`), because SARIF results from semgrep carry no per-result `level` (observed in the local test, see notes). Findings below ERROR are still uploaded and visible.
- CodeQL and dependency review need code scanning / dependency graph features: free on public repos; private repos need GitHub Code Security / Advanced Security. Without that, drop the job or use the semgrep and osv jobs.
- CodeQL does not fail the job on alerts. The blocking decision is a code scanning merge-protection setting (ruleset "Require code scanning results", threshold by severity), not a workflow step.
- Fork PRs: the read-only token means no PR comments from `dependency-review` (the job gate still works from its exit code), and SARIF uploads are skipped or guarded (semgrep, trivy, osv). CodeQL `analyze` upload on fork PRs was not verified; expect it to be skipped or to fail on the token, and check on a test fork before making it required.
- Merge queues: `merge_group:` is in the triggers so `security-gate` reports there. The PR-diff jobs (`secrets`, `dependency-review`, `osv`, `sast-semgrep`) read `github.event.pull_request.*`, which is empty on `merge_group` events, so they carry `if: ${{ github.event_name == 'pull_request' }}` and are skipped in the queue (a skipped job counts as a pass in `security-gate`; the queue run re-checks `sca`, CodeQL and `iac-container`). `branches: [main]` ignores PRs that target release branches: add those branches if they need the gate. This was linted, not run in a real merge queue.
- `security-gate` is the single required status check. A required check that is skipped counts as passing, so aggregate with `if: always()` and fail on `failure` or `cancelled`.

```yaml
# .github/workflows/pr-security.yml
# Staged PR security checks. Every third-party action is pinned to a full commit SHA
# (tag in the trailing comment, resolved 2026-11-25; re-resolve and review when bumping).
name: pr-security

on:
  pull_request:
    branches: [main]      # PRs targeting release branches are NOT covered; add them here
  merge_group:            # without this the required security-gate never reports in a merge queue

# Deny by default; each job asks for what it needs.
permissions: {}

concurrency:
  group: pr-security-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

jobs:
  secrets:
    name: secret scan (gitleaks)
    if: ${{ github.event_name == 'pull_request' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Install gitleaks (checksum-pinned CLI, no license key needed)
        run: |
          set -euo pipefail
          GL=8.30.1
          curl -sSfL -o gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GL}/gitleaks_${GL}_linux_x64.tar.gz"
          echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  gitleaks.tgz" | sha256sum -c -
          mkdir -p "$RUNNER_TEMP/gl" && tar xzf gitleaks.tgz -C "$RUNNER_TEMP/gl" gitleaks
      - name: Scan only the commits this PR adds
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          "$RUNNER_TEMP/gl/gitleaks" git --redact --exit-code 1 \
            --log-opts="${BASE_SHA}..${HEAD_SHA}" \
            --report-format sarif --report-path gitleaks.sarif .
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        if: ${{ !cancelled() }}
        with:
          name: gitleaks-sarif
          path: gitleaks.sarif
          if-no-files-found: ignore
          retention-days: 14

  dependency-review:
    name: dependency review (new vulnerable or disallowed dependencies)
    if: ${{ github.event_name == 'pull_request' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
      contents: read
      pull-requests: write   # only for comment-summary-in-pr; drop it and the input if you prefer no comments
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/dependency-review-action@bbc44d14a204704ccc493733616cd1e93a0321ec # v5.0.1
        with:
          fail-on-severity: high
          comment-summary-in-pr: on-failure

  sca:
    name: dependency audit (pip-audit / npm audit)
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: pip-audit (Python)
        if: ${{ hashFiles('requirements.txt') != '' }}
        run: |
          python3 -m venv "$RUNNER_TEMP/pa"
          "$RUNNER_TEMP/pa/bin/pip" install --quiet pip-audit==2.10.1
          # Suppress an accepted finding with: --ignore-vuln GHSA-xxxx  (record owner + expiry in .security/suppressions.yml)
          "$RUNNER_TEMP/pa/bin/pip-audit" -r requirements.txt --strict
      - name: npm audit (JavaScript/TypeScript, production dependencies, high and above)
        if: ${{ hashFiles('package-lock.json') != '' }}
        run: npm audit --omit=dev --audit-level=high

  osv:
    name: osv-scanner (only vulnerabilities introduced by the PR)
    if: ${{ github.event_name == 'pull_request' }}
    permissions:
      actions: read
      contents: read
      security-events: write
    # Reusable workflow from google/osv-scanner-action, pinned to the SHA of v2.7.1.
    uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml@32d3cd482bdadfb38b186c0ad1b031902d55d932 # v2.7.1
    with:
      fail-on-vuln: true
      # The reusable workflow uploads SARIF by default; fork PRs get a read-only token, so skip it there.
      upload-sarif: ${{ github.event.pull_request.head.repo.full_name == github.repository }}

  sast-semgrep:
    name: SAST (semgrep)
    if: ${{ github.event_name == 'pull_request' }}
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.12"
      - name: Install semgrep (pinned)
        run: python -m pip install --quiet semgrep==1.187.0
      - name: Scan, diff-aware against the PR base (report everything, gate below)
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
        run: |
          semgrep scan --config p/default --metrics=off --disable-version-check \
            --baseline-commit "$BASE_SHA" --sarif-output=semgrep.sarif
      - name: Gate on ERROR-level results only (WARNING/INFO stay visible but do not block)
        run: |
          # Semgrep stores severity on the rule (defaultConfiguration.level), not on each result.
          n=$(jq '(.runs[0].tool.driver.rules | map({(.id): (.defaultConfiguration.level // "warning")}) | add // {}) as $lv
                  | [.runs[].results[] | select(($lv[.ruleId] // .level // "warning") == "error")] | length' semgrep.sarif)
          echo "semgrep error-level results: $n"
          [ "$n" -eq 0 ]
      - uses: github/codeql-action/upload-sarif@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        # Fork PRs get a read-only token, so the upload would fail; skip it there.
        if: ${{ !cancelled() && github.event.pull_request.head.repo.full_name == github.repository }}
        with:
          sarif_file: semgrep.sarif
          category: semgrep

  sast-codeql:
    name: SAST (CodeQL ${{ matrix.language }})
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions:
      contents: read
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        language: [python, javascript-typescript]   # keep only the languages the repo contains
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: github/codeql-action/init@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        with:
          languages: ${{ matrix.language }}
          build-mode: none
      - uses: github/codeql-action/analyze@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        with:
          category: "/language:${{ matrix.language }}"

  iac-container:
    name: IaC and container scan (trivy)
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: IaC misconfiguration scan (Terraform, Kubernetes, Dockerfile, Helm)
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: config
          scan-ref: .
          severity: HIGH,CRITICAL
          exit-code: "1"
          format: sarif
          output: trivy-iac.sarif
      - name: Build image for scanning (no push)
        if: ${{ !cancelled() && hashFiles('Dockerfile') != '' }}
        run: docker build -t pr-image:scan .
      - name: Image vulnerability scan (fixable HIGH/CRITICAL only)
        if: ${{ !cancelled() && hashFiles('Dockerfile') != '' }}
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          image-ref: pr-image:scan
          severity: HIGH,CRITICAL
          ignore-unfixed: true
          exit-code: "1"
          format: sarif
          output: trivy-image.sarif
      - uses: github/codeql-action/upload-sarif@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        if: ${{ !cancelled() && hashFiles('trivy-iac.sarif') != '' && github.event.pull_request.head.repo.full_name == github.repository }}
        with:
          sarif_file: trivy-iac.sarif
          category: trivy-iac
      - uses: github/codeql-action/upload-sarif@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        if: ${{ !cancelled() && hashFiles('trivy-image.sarif') != '' && github.event.pull_request.head.repo.full_name == github.repository }}
        with:
          sarif_file: trivy-image.sarif
          category: trivy-image

  # One stable check name for branch protection / rulesets. Skipped matrix or conditional jobs
  # cannot silently satisfy a required check this way.
  # Note: `skipped` upstream results count as a pass here (the PR-only jobs are skipped in merge queues),
  # so no job may be skipped by a top-level `if:` unless that is intended.
  security-gate:
    name: security-gate
    if: ${{ always() }}
    needs: [secrets, dependency-review, sca, osv, sast-semgrep, sast-codeql, iac-container]
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    permissions: {}
    steps:
      - name: Fail if any upstream job failed or was cancelled
        env:
          NEEDS_JSON: ${{ toJSON(needs) }}
        run: |
          echo "$NEEDS_JSON" | jq -r 'to_entries[] | "\(.key): \(.value.result)"'
          echo "$NEEDS_JSON" | jq -e '[.[] | select(.result=="failure" or .result=="cancelled")] | length == 0' >/dev/null
```

## 2. `release.yml` (tag push: scan, SBOM, sign, attest)

Notes:

- Runs only on tags; put `v*` tags under a tag protection / ruleset so only maintainers create them. Add required reviewers on the `release` environment for a human gate.
- `id-token: write` is granted to this one job only. `artifact-metadata: write` is also needed because both attest steps use `push-to-registry: true` (`actions/attest` creates a storage record by default); alternatively set `create-storage-record: false` on them. Whether a missing permission warns or fails was not verified on a runner. Keyless signing uses the workflow identity as certificate subject, so there is no signing key to leak.
- Scan, SBOM, signature and attestations all target the immutable **digest**, not the tag.
- `actions/attest-build-provenance` v4 and `actions/attest` v4 are the GitHub artifact-attestation actions; `subject-name` for registries is the image name without tag. For private repos attestations need a plan that supports them (README of the action).
- `cosign sign --yes` is the keyless flow (Fulcio certificate, Rekor entry). Use one of cosign signature or GitHub attestation as the verifiable source of truth; consumers should verify with a pinned identity (see Verification below).
- If the scan fails, the image already exists in the registry (unsigned and without attestation). Do not deploy unsigned digests; admission policy should require the signature.

```yaml
# .github/workflows/release.yml
# Tag-triggered release: build, scan the pushed digest, SBOM, keyless signature, provenance.
# Pin every action to a full SHA (tag in comment, resolved 2026-11-25).
name: release

on:
  push:
    tags: ["v*"]

permissions: {}

jobs:
  publish:
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    environment: release          # add required reviewers on this environment for a manual approval gate
    permissions:
      contents: read
      packages: write             # push to ghcr.io
      id-token: write             # OIDC token for keyless signing and attestations
      attestations: write         # store attestations
      artifact-metadata: write    # storage record (attest default create-storage-record: true)
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Lower-case image name (registry requires it)
        run: echo "IMAGE=ghcr.io/${GITHUB_REPOSITORY,,}" >> "$GITHUB_ENV"

      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1
      - uses: docker/login-action@8aa5831fb8d48d8f76594c7ddde61ae58019f550 # v4.8.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        id: build
        uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          context: .
          push: true
          tags: ${{ env.IMAGE }}:${{ github.ref_name }}

      - name: Scan the pushed digest (fail the release on fixable HIGH/CRITICAL)
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          image-ref: ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
          severity: HIGH,CRITICAL
          ignore-unfixed: true
          exit-code: "1"

      - name: Generate SBOM (CycloneDX JSON)
        uses: anchore/sbom-action@dfcb83b97731532d72be422cbc51ee64adb6fd56 # v0.24.4
        with:
          image: ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
          format: cyclonedx-json
          output-file: sbom.cdx.json
          artifact-name: sbom.cdx.json

      - uses: sigstore/cosign-installer@881c63bd87e38389154debd8331404ce7ca8a3ab # v4.1.4

      - name: Keyless-sign the image digest (identity = this workflow, via OIDC)
        env:
          DIGEST: ${{ steps.build.outputs.digest }}
        run: cosign sign --yes "${IMAGE}@${DIGEST}"

      - name: Attest SLSA build provenance
        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-name: ${{ env.IMAGE }}
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true

      - name: Attest the SBOM
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with:
          subject-name: ${{ env.IMAGE }}
          subject-digest: ${{ steps.build.outputs.digest }}
          sbom-path: sbom.cdx.json
          push-to-registry: true
```

Verify what the release produced (consumer side):

```bash
# GitHub attestations (provenance is the default predicate type)
gh attestation verify oci://ghcr.io/OWNER/REPO@sha256:DIGEST --repo OWNER/REPO
# cosign keyless signature: pin the workflow identity and the issuer
cosign verify ghcr.io/OWNER/REPO@sha256:DIGEST \
  --certificate-identity "https://github.com/OWNER/REPO/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

(`gh attestation verify` flags `--repo`, `--owner`, `--signer-workflow`, `--predicate-type` and `cosign verify` flags `--certificate-identity[-regexp]`, `--certificate-oidc-issuer` exist in the installed CLIs; the verify commands themselves were not run because no image was published.)

## 3. `dast.yml` (ephemeral stack, passive baseline, written scope)

DAST is slower and noisier, so it is scheduled or manual rather than a PR gate. The job refuses to run unless `.security/dast-scope.json` exists, is unexpired and authorises `localhost` (the stack started inside the job). Scope format matches the suite's scope rules (`authorized_by`, `environment` lab or staging, `targets`, `isolation_confirmed`, `expires`). ZAP baseline only runs passive rules; active scanning or any non-localhost target needs its own written scope, test accounts and synthetic data. Never point it at production.

```json
{"authorized_by": "service owner (role)", "environment": "lab", "targets": ["localhost"],
  "isolation_confirmed": true, "expires": "2027-03-31T00:00:00Z"}
```

```yaml
# .github/workflows/dast.yml
# DAST baseline (passive) against an ephemeral stack started inside the job. Never point it at
# production or at a host you have not been authorised to test.
name: dast-baseline

on:
  workflow_dispatch:
  schedule:
    - cron: "17 3 * * 1"     # weekly, Monday 03:17 UTC

permissions: {}

jobs:
  zap-baseline:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Require a current written scope for this target
        run: |
          python3 - <<'PY'
          import json, sys, datetime
          s = json.load(open(".security/dast-scope.json"))
          need = ["authorized_by", "environment", "targets", "isolation_confirmed", "expires"]
          missing = [k for k in need if k not in s]
          if missing: sys.exit(f"scope missing keys: {missing}")
          if s["environment"] not in ("lab", "staging"): sys.exit("environment must be lab or staging")
          if s["isolation_confirmed"] is not True: sys.exit("isolation not confirmed")
          if "localhost" not in s["targets"]: sys.exit("localhost (the ephemeral stack) is not an authorised target")
          exp = datetime.datetime.fromisoformat(s["expires"].replace("Z", "+00:00"))
          if exp <= datetime.datetime.now(datetime.timezone.utc): sys.exit("scope expired")
          print("scope OK until", s["expires"])
          PY

      - name: Start the ephemeral stack with synthetic data
        run: |
          docker compose -f compose.ci.yml up -d --wait
          curl -fsS http://localhost:8080/healthz

      - name: ZAP baseline scan (passive rules only, no attack payloads)
        uses: zaproxy/action-baseline@de8ad967d3548d44ef623df22cf95c3b0baf8b25 # v0.15.0
        with:
          target: http://localhost:8080
          rules_file_name: .zap/rules.tsv     # per-rule IGNORE/WARN/FAIL; keep reasons and owners in the file's comments
          fail_action: true
          allow_issue_writing: false          # avoids needing issues: write

      - name: Tear down
        if: ${{ always() }}
        run: docker compose -f compose.ci.yml down -v
```

`compose.ci.yml`, `/healthz` and `.zap/rules.tsv` are placeholders you must provide (the rules file format is described in the ZAP baseline docs). `zaproxy/action-baseline` v0.15.0 inputs used: `target`, `rules_file_name`, `fail_action`, `allow_issue_writing`.

## 4. `scheduled-security.yml` (default branch and weekly: full scans)

PR checks only see changed code. This workflow covers pipeline stage 3 and the weekly full scan: new advisories against old code, a baseline refresh on `main`, and CodeQL analysis of the default branch (the code scanning merge-protection ruleset needs a result on the default branch to compare against). It does not enforce suppression expiry: that job is yours to write (see [gate-policy-and-rollout.md](gate-policy-and-rollout.md)). Same pins as the PR workflow; `permissions: {}` at workflow level and per-job grants. Linted with `actionlint` and `shellcheck`, not run on a runner. Full-history and full-tree scans report everything, including pre-existing findings, so the jobs fail the run (red scheduled run, notify the code owner) rather than any PR.

```yaml
# .github/workflows/scheduled-security.yml
# Default-branch and weekly full scans. Every third-party action is pinned to a full commit SHA
# (tag in the trailing comment, resolved 2026-11-25; re-resolve and review when bumping).
name: scheduled-security

on:
  push:
    branches: [main]
  schedule:
    - cron: "41 2 * * 1"     # weekly, Monday 02:41 UTC
  workflow_dispatch:

permissions: {}

concurrency:
  group: scheduled-security-${{ github.ref }}
  cancel-in-progress: false

jobs:
  codeql:
    name: CodeQL ${{ matrix.language }} (default branch)
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions:
      contents: read
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        language: [python, javascript-typescript]   # keep only the languages the repo contains
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: github/codeql-action/init@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        with:
          languages: ${{ matrix.language }}
          build-mode: none
      - uses: github/codeql-action/analyze@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        with:
          category: "/language:${{ matrix.language }}"   # same category as the PR workflow

  osv-full:
    name: osv-scanner (full tree, known advisories)
    permissions:
      actions: read
      contents: read
      security-events: write
    # Reusable workflow from google/osv-scanner-action, pinned to the SHA of v2.7.1.
    uses: google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@32d3cd482bdadfb38b186c0ad1b031902d55d932 # v2.7.1
    with:
      fail-on-vuln: true

  gitleaks-history:
    name: secret scan (gitleaks, full history)
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Install gitleaks (checksum-pinned CLI, no license key needed)
        run: |
          set -euo pipefail
          GL=8.30.1
          curl -sSfL -o gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GL}/gitleaks_${GL}_linux_x64.tar.gz"
          echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  gitleaks.tgz" | sha256sum -c -
          mkdir -p "$RUNNER_TEMP/gl" && tar xzf gitleaks.tgz -C "$RUNNER_TEMP/gl" gitleaks
      - name: Scan the whole history (findings are redacted in output and report)
        run: |
          "$RUNNER_TEMP/gl/gitleaks" git --redact --exit-code 1 \
            --report-format sarif --report-path gitleaks.sarif .
      - uses: github/codeql-action/upload-sarif@915412ff23e8b7659517e607487dbeae018f2934 # v4.39.5
        if: ${{ !cancelled() && hashFiles('gitleaks.sarif') != '' }}
        with:
          sarif_file: gitleaks.sarif
          category: gitleaks
```

## Optional: the project's `security-skills` CLI as one more step

Not on PyPI; install from GitHub and pin a commit before relying on it. Exit codes observed locally: `0` when nothing counts, `1` when the gate fails. Default `--gate candidates` counts confirmed findings and high-confidence candidates; `--gate confirmed` only independently validated ones; `--strict` also counts every non-rejected candidate.

```yaml
      - name: security-skills audit (workflow and supply-chain review, offline)
        run: |
          python -m pip install "git+https://github.com/shikari00007/security-test-automation.git@COMMIT_SHA"   # pin before use
          security-skills audit . --type supply-chain --report sarif --output-dir "$RUNNER_TEMP/ss" --fail-on high
```

`--output-dir` must be outside the audited tree. Upload `$RUNNER_TEMP/ss/results.sarif` with `upload-sarif` like the other jobs.

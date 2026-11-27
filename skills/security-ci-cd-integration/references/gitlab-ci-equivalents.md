# GitLab CI equivalents (brief)

GitLab ships maintained templates, so the pipeline is mostly `include:` lines. Template names and job names below were fetched from `gitlab-org/gitlab` (`lib/gitlab/ci/templates/Security/`) on 2026-11-25. The file parsed with `yaml.safe_load` and passed `yamllint`; it was not run in a GitLab pipeline (no GitLab instance available), and GitLab's CI Lint was not used. Stage order (`build`, `test`, `release`) and the `needs:` link from `sign-image` to `build-image` were checked by hand against the template stages. The build job is a minimal kaniko example, untested: replace it with your own build.

```yaml
# .gitlab-ci.yml (security part). GitLab-maintained templates, verified to exist 2026-11-25.
# The templates' scan jobs default to allow_failure: true and the analyzers report findings through
# report artifacts rather than failing the job. Blocking on findings is a merge-request approval /
# security policy setting (tier dependent), not something these jobs do by themselves.
stages: [build, test, release]   # Container-Scanning runs in `test`, so the image must exist by then

include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/SAST-IaC.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml

variables:
  SAST_EXCLUDED_PATHS: "spec, test, tests, tmp, fixtures"
  SECRET_DETECTION_EXCLUDED_PATHS: "tests/fixtures"
  CS_IMAGE: "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"     # image pushed by build-image below

# Cancel superseded pipelines (not a security control).
default:
  interruptible: true

# Minimal build job: pushes the image and passes its digest on through a dotenv artifact.
build-image:
  stage: build
  image:
    name: gcr.io/kaniko-project/executor:debug      # pin by digest before use
    entrypoint: [""]
  script:
    - mkdir -p /kaniko/.docker
    - printf '{"auths":{"%s":{"auth":"%s"}}}' "$CI_REGISTRY" "$(printf '%s:%s' "$CI_REGISTRY_USER" "$CI_REGISTRY_PASSWORD" | base64 | tr -d '\n')" > /kaniko/.docker/config.json
    - /kaniko/executor --context "$CI_PROJECT_DIR" --dockerfile "$CI_PROJECT_DIR/Dockerfile" --destination "$CS_IMAGE" --digest-file digest.txt
    - echo "IMAGE_DIGEST=$(cat digest.txt)" > build.env
  artifacts:
    reports:
      dotenv: build.env

# Keyless signing with the job's OIDC identity (cosign reads SIGSTORE_ID_TOKEN). Not executed here.
# On tag pipelines build-image must also run (it has no rules, so it does).
sign-image:
  stage: release
  needs:
    - job: build-image
      artifacts: true      # brings IMAGE_DIGEST from the dotenv report
  rules:
    - if: $CI_COMMIT_TAG
  image:
    name: gcr.io/projectsigstore/cosign:v3.1.5      # pin by digest before use
    entrypoint: [""]
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore
  script:
    - cosign sign --yes "$CI_REGISTRY_IMAGE@$IMAGE_DIGEST"   # IMAGE_DIGEST passed from the build job via dotenv
```

## Mapping

| Stage | GitHub Actions | GitLab CI |
|---|---|---|
| Secrets | gitleaks CLI | `Security/Secret-Detection` (job `secret_detection`) |
| SAST | semgrep, CodeQL | `Security/SAST` (job `sast` plus per-language analyzers) |
| Dependencies | dependency-review, pip-audit, npm audit, osv-scanner | `Security/Dependency-Scanning` (job `dependency_scanning`) |
| IaC | trivy config | `Security/SAST-IaC` |
| Container | trivy image | `Security/Container-Scanning` (job `container_scanning`, set `CS_IMAGE`) |
| Reporting | SARIF upload to code scanning | `artifacts:reports:*` consumed by the Security tab and MR widget |
| Blocking | rulesets + required checks | protected branches, "Pipelines must succeed", and merge request approval/security policies (tier dependent; check your plan) |
| OIDC | `id-token: write` | `id_tokens:` with an `aud` |
| Signing | cosign + attest actions | cosign with `SIGSTORE_ID_TOKEN` from `id_tokens` (`id_tokens` with `SIGSTORE_ID_TOKEN` is shown in GitLab's `ci/yaml` docs; verify against current GitLab and cosign docs) |

## GitLab-specific cautions

- Template jobs are `allow_failure: true` by default and analyzers do not exit non-zero on findings, so a green pipeline does not mean "no findings". Decide the gate through policy, as in [gate-policy-and-rollout.md](gate-policy-and-rollout.md).
- Protected and masked CI/CD variables: mark secrets `Protected` so they only reach protected branches and tags; fork merge-request pipelines should not receive them.
- Pin `include:` to a version where possible (`include: project:` with `ref:` a commit SHA, or the versioned template), and pin job images by digest.
- Use `rules:` to run the heavy jobs (container, DAST) on the default branch and tags, and the fast ones on merge requests.

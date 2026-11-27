---
name: secrets-management
description: "Use when the user says things like \"where should I put this API key\", \"I committed a secret, what now\", \"is it a problem that my app falls back to a default SECRET_KEY or password if the env var is missing\", \"is it ok to hardcode this token\", \"add secret scanning\", \"stop leaking tokens in logs\", \"use OIDC instead of AWS keys in CI\". Keeps secrets out of code, logs, bundles and git history: fail-fast config, .env hygiene, secret stores (Vault, SOPS, cloud, Kubernetes), rotation, redaction, public vs secret keys, leak response (revoke first, history rewrite). Not for: workflow permission/pin/injection review that merely mentions OIDC, dependency hardening (supply-chain-security), IAM/RBAC/manifest review (cloud-kubernetes-security), pipeline gate design (security-ci-cd-integration), triaging a findings backlog (vulnerability-triage-and-fix), login/session/password design (authn-authz-implementation). Related: secure-coding-patterns, security-unit-testing, security-code-review, security-project-context."
license: MIT
compatibility: Any Agent Skills runtime with file read and shell access. Optional gitleaks, pre-commit, detect-secrets, git-filter-repo for the commands shown; security-skills CLI is never required.
metadata:
  author: security-test-automation contributors
  version: "0.4.0"
  category: build
---

# Secrets Management

> **Developer Preview.** Guidance and checks, not a guarantee. Claim "these checks passed", never "secure".

**Objective.** Prevent the concrete failures that cause most credential incidents: a real key committed in a `.env` or test fixture and pushed; a config default that silently falls back to a production-looking secret; a server key bundled into frontend JavaScript; a token printed by a logger or error page; a leak "fixed" by deleting the file while the credential still works. Also give a correct response when it has already happened.

## When this applies / does not apply

- Applies: any code that reads, stores, passes, logs, tests with or ships a credential; adding or reviewing `.env`, config modules, CI secrets, pre-commit hooks; a suspected leak.
- Does not apply: reviewing dependencies or workflow permissions in general -> `supply-chain-security`; IAM, RBAC, Terraform or manifest review -> `cloud-kubernetes-security`; designing pipeline gates and required checks -> `security-ci-cd-integration`; ranking and fixing a findings backlog -> `vulnerability-triage-and-fix`; passwords of end users, sessions, JWT verification -> `authn-authz-implementation`.

## Discovery questions (ask at most these)

First read `.agents/security-project-context.md` if present and do not re-ask what it answers.
1. Language/framework and where the app runs (laptop, container, serverless, Kubernetes, VM)? 
2. Which secrets exist (DB, third-party API, signing keys, webhook secrets) and who consumes each (server, CI, browser, mobile)?
3. Is there an existing store (cloud secret manager, Vault, SOPS) or only `.env`/CI variables?
4. Is a leak suspected or confirmed? Which credential, which repo/remote, public or private, how long exposed?
5. Does the repo have a pre-commit config or CI secret scan already?

## Workflow

1. **Inventory (produce a table).** List each secret: name, consumer, current location, blast radius if leaked, rotation owner. Use [references/where-secrets-live.md](references/where-secrets-live.md) to classify what is a secret and pick the home. Done when every secret has one decided home.
2. **Search the repo and history for what is already exposed.** Run `gitleaks dir --redact --no-banner .` and `gitleaks git --redact --no-banner .` (or `grep` if not installed) and review `.gitignore`. Anything real found -> jump to step 8 first; do not continue building on a leaked credential.
3. **Load config safely.** Implement one config module: required secrets have no default, startup fails with the variable *name* only, secrets use a masking type, `.env` is ignored and a placeholder `.env.example` is committed. Patterns for Python (pydantic-settings) and Node in [references/safe-config-loading.md](references/safe-config-loading.md). Done when a test proves missing config fails fast and `repr()`/JSON does not show values.
4. **Move secrets to the chosen store.** Prefer identity-based access (workload identity, OIDC in CI) over stored keys; scope each credential to the minimum and give it an expiry or rotation path. Decision table and recipes: [references/where-secrets-live.md](references/where-secrets-live.md).
5. **Add prevention.** Install the pre-commit config and gitleaks config from [references/leak-prevention-scanning.md](references/leak-prevention-scanning.md) and a CI scan job (hand pipeline policy to `security-ci-cd-integration`). Done when a planted fake credential makes the hook fail and the clean tree passes.
6. **Redact output.** Add the redaction helper from [references/redaction-and-test-fixtures.md](references/redaction-and-test-fixtures.md) to log handlers and error reporters; never log request headers or full config. Done when a test logs a fake token and asserts it is absent.
7. **Fix fixtures and client code.** Tests use synthetic, obviously fake values; the browser bundle only gets public identifiers (see public vs secret keys in [references/safe-config-loading.md](references/safe-config-loading.md)). Done when a scan of `tests/` and the built bundle is clean.
8. **If a secret leaked, follow the incident order** in [references/incident-response.md](references/incident-response.md): revoke/rotate, then audit use, then clean history, notify, prevent. Produce an incident note (what, when exposed, rotated at, audit result, follow-ups).

## Secure-by-default rules

- No real secret in source, tests, docs, Dockerfiles, build args, images, CI YAML or client bundles.
- Required secrets have no default value, not even a "dev" one that works in production; missing -> fail at startup, naming the variable only.
- `.env`, `.env.*` (except `.env.example`), key files and `*.tfvars` with secrets are in `.gitignore` before the first commit.
- Never put a secret in a URL, query string, command-line argument or log line.
- Prefer short-lived, identity-based credentials (OIDC, workload identity) to long-lived keys; one credential per consumer and environment.
- Least privilege per secret: a read-only DB user for a read-only service; a scoped token, not an account owner key.
- Scan twice: locally at commit time and again in CI (hooks can be skipped).
- Never allowlist a finding to silence it before deciding it is a real secret or a fake; allowlist narrowly (path or regex plus a comment).
- A leaked secret is compromised until rotated; deleting the commit does not change that.
- Never disable the scanner, `--no-verify` or skip hooks to get a commit through.

## Verification

Show, do not assert:
- Config test: missing variable raises with the variable name and no value; `repr`/`JSON.stringify` of config hides secrets.
- Scanner proof: scan fails on a planted synthetic credential and passes on the clean tree (run `gitleaks` or `pre-commit run --all-files`; if the tool is not installed say "not executed").
- Redaction test passes for a fake token in message, dict key and exception text.
- For an incident: show the old credential rejected by the provider (a failed auth call or provider console state) and the history scan clean after rewrite.
Report as "these checks passed", list what was not run.

## Examples

**Triggers.** "I accidentally pushed my Stripe key to GitHub, what do I do?" -> step 8: rotate the key in the Stripe dashboard first, review Stripe request logs for the exposure window, then remove from history (rewriting does not un-leak it), then add the hook.

**Does not trigger.** "Review this GitHub Actions workflow for pinned actions and `pull_request_target` risks" -> `supply-chain-security`. "Our JWT verification accepts alg none" -> `authn-authz-implementation`. "Triage these 200 gitleaks findings from last year" -> `vulnerability-triage-and-fix` (come back here only to rotate confirmed ones).

## Integration

- `security-ci-cd-integration`: owns the pipeline job, required checks and SARIF upload; this skill supplies the scan config and OIDC pattern.
- `cloud-kubernetes-security`: reviews IAM scope, Kubernetes RBAC and Secret manifests; this skill chooses what lives where.
- `supply-chain-security`: workflow permissions, pinned actions, build-time secret exposure.
- `security-unit-testing`: turn the config and redaction checks into permanent tests.
- `security-project-context`: record the store, rotation owners and scan ignore paths (never the secrets).
- Optional CLI: `security-skills skills validate skills` checks this skill's format.

## Limitations

- Pattern scanners miss custom or low-entropy secrets (passwords, internal tokens) unless you add rules, and flag fakes; they confirm presence, not safety.
- History rewriting cannot recall clones, forks, caches, CI logs or crawlers; only rotation neutralises a leak.
- Provider audit-log retention and detail differ; some providers log little. State "not determinable" rather than "no misuse".
- Recipes cover Python and Node first; Java/Go use the same decision table with their own config libraries.
- Store-specific syntax (Vault policies, SOPS rules, sealed-secrets setup) is summarised, not exhaustively verified; check current vendor docs before applying.
- Standards cited are OWASP ASVS 5.0.0 V13.3 and the OWASP Secrets Management Cheat Sheet (undated web edition, checked 2026-11-25); see `references/VERIFICATION-NOTES.md`.

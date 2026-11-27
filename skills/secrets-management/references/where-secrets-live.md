# Where should this secret live

## What counts as a secret

Treat as secret anything that grants access or lets someone impersonate or decrypt: passwords, API keys and tokens, OAuth client secrets and refresh tokens, database URLs with credentials, private keys (TLS, SSH, JWT/signing, age/PGP), webhook signing secrets, session/cookie signing keys, encryption keys, service-account JSON, cloud access keys, CI tokens, seeds for one-time codes (ASVS 5.0.0 13.3.1 lists passwords, key material, database and third-party integration credentials, time-based token seeds, API keys).

Not secret (but still configuration): public/publishable keys (for example a payment provider's publishable key, a maps key restricted by referrer, an OAuth client *id*), feature flags, hostnames, ports. A "public" key is only safe when the provider designs it for the browser *and* you applied its restrictions (referrer/origin, scope). When unsure, treat as secret and ask which side of the trust boundary consumes it.

## Decision table

| Secret / situation | Best home | Avoid |
|---|---|---|
| Server runtime secret on a cloud VM/container/serverless | Cloud secret manager (AWS Secrets Manager / SSM Parameter Store SecureString, GCP Secret Manager, Azure Key Vault) read via the workload's own identity (IAM role, managed identity) | Baking into the image, `ENV`/`ARG` in Dockerfile, build-time injection |
| Multi-cloud or dynamic secrets (short-lived DB creds, PKI) | HashiCorp Vault (or compatible) with short leases | One shared static admin credential |
| Secrets that must live in git for GitOps/IaC | Encrypted at rest in the repo: SOPS (KMS/age/PGP backends) or Sealed Secrets for Kubernetes; decryption key held outside the repo | Plain base64 Kubernetes Secret manifests in git |
| Kubernetes workload | External store via CSI driver/operator or sidecar, or native Secret with encryption at rest + tight RBAC; mount as files | Secret as env var by default; broad `get/list` on Secrets |
| CI/CD deploying to cloud | OIDC federation (short-lived token minted per job) with a trust condition on repo/branch/environment | Long-lived cloud keys stored as CI variables |
| CI needs a third-party token (no OIDC support) | CI secret scoped to one environment/repo, masked, rotated on a schedule | Org-wide secret available to every repo and fork PR |
| Local development | `.env` (git-ignored) with dev-only credentials, or a developer-scoped sandbox account; secret manager CLI for shared dev secrets | Copying production secrets to laptops |
| Automated tests | Synthetic fake values; mocks/local emulators; test-mode keys of a sandbox account only if unavoidable, injected at runtime | Real keys in fixtures, snapshots, recorded cassettes |
| Browser / mobile app | Only public identifiers. Anything secret stays behind your backend, which calls the third party | Server key in `NEXT_PUBLIC_*`/`VITE_*`/bundle; "obfuscated" keys in mobile binaries |
| Signing/encryption keys | KMS/HSM-backed keys where the app asks the service to sign/decrypt, key never leaves | Key material in app config |
| Break-glass / recovery | Offline, access-audited, tested restore procedure | Single person's password manager |

Source for the CI/Kubernetes/OIDC rows: OWASP Secrets Management Cheat Sheet sections CI/CD and Containers & Orchestrators (prefer OIDC/workload identity to static keys; never bake secrets with ENV/ARG; sidecar or mounted volumes preferred, env vars last resort). Kubernetes docs: Secrets are stored unencrypted in etcd by default; enable encryption at rest, least-privilege RBAC, consider an external store (kubernetes.io/docs/concepts/configuration/secret/).

## Least privilege and rotation

- One credential per consumer *and* environment, so revoking one does not break others and logs identify the caller (ASVS 5.0.0 13.3.2: access to secrets follows least privilege).
- Scope: read-only DB role for read-only paths; per-bucket/per-prefix IAM; fine-grained tokens with the minimum scopes and an expiry. Avoid wildcard `iam:PassRole`-style grants (cheat sheet: avoid open "pass role" privileges).
- Document each security-critical secret and its rotation schedule (ASVS 5.0.0 13.1.4, L3) and configure expiry/rotation (13.3.4, L3). Prefer automated rotation or dynamic short-lived credentials; restart-only does not revoke a stolen credential.
- Rotation without downtime: create the new credential, deploy consumers reading the new value (dual-valid window), verify, then revoke the old. Keep a rotation runbook beside the inventory.
- Service-to-service: prefer individual service accounts, short-lived tokens or certificates over static shared keys (ASVS 5.0.0 13.2.1); never ship default credentials (13.2.3).
- Audit: enable the store's access logs and alert on failed or unusual reads.

## GitHub Actions OIDC (AWS example, from GitHub docs)

```yaml
permissions:
  id-token: write   # required to request the JWT
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: prod            # makes the sub claim environment-based
    steps:
      - uses: aws-actions/configure-aws-credentials@<full-commit-sha>
        with:
          role-to-assume: arn:aws:iam::123456789012:role/example-deploy-role   # placeholder
          aws-region: us-east-1
```

Trust policy condition on the role (restrict, do not leave open to every repo):

```json
"Condition": {
  "StringEquals": {
    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
    "token.actions.githubusercontent.com:sub": "repo:ORG/REPO:environment:prod"
  }
}
```

GitHub notes newer repositories may use an immutable `sub` format that includes owner and repository IDs; confirm the exact claim string for your repo in GitHub's OIDC docs before writing the condition. Do not put the `id-token: write` permission on workflows that run untrusted fork code.

## SOPS and Kubernetes notes

- SOPS edits encrypted YAML/JSON/ENV/INI/binary files and supports AWS KMS, GCP KMS, Azure Key Vault, age and PGP (README). `sops decrypt FILE` prints plaintext; `sops edit FILE` decrypts, opens an editor and re-encrypts. `.sops.yaml` creation-rule syntax was not verified for this skill: read getsops.io/docs/usage/identities/config-file/ and keep the private key out of the repo.
- Sealed Secrets (Kubernetes) lets you commit only encrypted objects decryptable by the in-cluster controller; syntax and key backup are not verified here, follow the project docs. Back up the controller key or you cannot recover.
- Whatever the store, apps read values at startup via a config layer ([safe-config-loading.md](safe-config-loading.md)) so the store can change without code edits.

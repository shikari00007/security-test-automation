# Cloud and Kubernetes methodology

## Kubernetes workloads
- `privileged: true`, `allowPrivilegeEscalation: true`, `hostNetwork/hostPID/hostIPC`, `hostPath` mounts (especially docker socket), added capabilities, running as root (`runAsNonRoot` absent), writable root filesystem, `latest` or unpinned images, missing resource limits (note for review, not DoS testing), service account token auto-mounted unnecessarily, secrets in plain `env`.
- Secure: restricted Pod Security Standard profile, seccomp `RuntimeDefault`, drop all capabilities.

## RBAC and cluster access
- `cluster-admin` bindings to broad subjects, wildcard verbs/resources, `escalate/bind/impersonate`, default service account with permissions, anonymous access.

## Network and exposure
- No NetworkPolicy (flat network), services of type LoadBalancer or NodePort exposing admin interfaces, Ingress without TLS, public API server endpoint.

## Cloud resources (Terraform/CloudFormation)
- Public storage buckets, security groups open to `0.0.0.0/0` on admin ports, wildcard IAM actions or resources, missing encryption at rest or in transit, disabled logging and flow logs, public databases, hardcoded credentials, state files containing secrets.

## Images and secrets
- Dockerfile `USER root`, secrets in layers, unpinned base images; secrets committed in manifests or Helm values (use external secret stores).

## Admission and policy
- Absence of Pod Security Admission labels, OPA/Gatekeeper or Kyverno policies; audit logging disabled.

## Mapping to reviewed checks

Match each category above to executable check IDs in [catalog checks](catalog-checks.md); anything without a reviewed ID is a manual check and stays `planned` or `blocked` until performed with evidence.

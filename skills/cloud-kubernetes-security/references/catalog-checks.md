# Catalog checks for cloud-kubernetes

Reviewed, executable checks. Load on demand; do not copy the catalog into prompts.

- List: `security-skills catalog checks cloud-kubernetes`
- The large normalized catalog is a maintainer-internal artifact and is not part of the public release; rely on the reviewed checks above and the methodology reference.
- Without the CLI use the methodology reference; all checks there are manual.

Snapshot of reviewed check IDs when this skill was built (the CLI is authoritative):

| ID | Mode | Severity | Title |
|---|---|---|---|
| SEC-K8S-001 | static | high | Privileged containers, privilege escalation, host namespaces or hostPath mounts |
| SEC-K8S-002 | static | medium | Containers run as root (runAsUser 0 or runAsNonRoot false) |
| SEC-K8S-003 | static | medium | Dockerfile with unpinned or latest base image, no USER, or curl-pipe-shell |
| SEC-K8S-004 | static | high | Terraform open admin ingress, public S3 ACL or unencrypted S3 bucket |
| SEC-K8S-005 | static | high | Plaintext Secret manifest with data committed to source |
| SEC-K8S-006 | static | high | cluster-admin bindings or wildcard RBAC rules |
| SEC-K8S-050 | dynamic | high | Live cluster RBAC audit using read-only authorized API access |

# Dynamic and manual procedures

> Everything in this file is manual or dynamic and requires written scope (authorized_by, lab or staging environment, explicit targets, expiry, isolation confirmed, test accounts) before any step. Without it the corresponding checks stay `blocked`. No credential attacks, no DoS or load, no production, no data beyond synthetic accounts. If the owner has not authorized it in writing, do not do it.

## Procedures (read-only live audit; lab or staging; written scope)

1. With owner-issued read-only credentials, `kubectl get` for workloads, roles, bindings, network policies and namespaces; export to files and analyze offline.
2. `kubectl auth can-i --list` as the issued identity to document effective permissions.
3. Cloud read APIs (describe/list only) for storage, IAM and security group configuration.
4. Optional benchmark run (CIS tooling such as kube-bench) on a lab node.

Never `exec` into pods, create or delete resources, escalate privileges, test privilege escalation paths, or touch production.

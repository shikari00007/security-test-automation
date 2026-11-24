# Risk prioritization

Rank domains and categories, then spend depth where risk is highest.

1. Exposure: internet-facing, partner-facing, internal, offline.
2. Data: credentials, payment, health, personal, tenant-isolated data raise priority.
3. Trust model: multi-tenant, SSO, third-party integrations, privileged admin surfaces.
4. Change rate: files changed in the PR or release.
5. Existing controls and past findings (regression history).

Typical top categories: access control and authentication for web/API; storage and network for mobile; update channel and IPC for desktop; CI permissions and secret handling for supply chain; privileged pods and IAM for cloud; excessive agency and output handling for AI.

Record the reasoning in one line per domain so a reviewer can disagree with it. Risk ordering changes order and depth, never the safety gates.

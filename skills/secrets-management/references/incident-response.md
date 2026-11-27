# When a secret leaked

Order matters. Rotation is the fix; everything else is cleanup and learning. Both the OWASP cheat sheet (Incident Response: contain via revocation, rotation, deletion, logging; history rewriting has side effects) and GitHub's removal guide ("revoke or rotate first") agree. Do not spend the first hour on git surgery while the credential still works.

Treat a secret as leaked if it was pushed to any remote, pasted in a ticket/chat, printed in CI or app logs, shipped in a bundle/image/artifact, or committed even locally and shared. Public exposure: assume harvested within minutes by bots.

## Sequence

| # | Step | Output / proof |
|---|---|---|
| 0 | Declare it: who is incident owner, open a private note (never paste the secret itself; use the last 4 chars or a fingerprint) | incident note |
| 1 | **Revoke or rotate** at the provider. Create the replacement first if the service must stay up, deploy it, then revoke the old one. Prefer revoke-now for public exposure and accept brief downtime | provider shows old credential disabled; a call with the old credential is rejected |
| 2 | Update consumers (secret store, CI variables, deployments) and confirm the app works with the new secret | health check, deploy log |
| 3 | **Assess blast radius** from provider audit logs for the whole exposure window (first commit/paste time to revocation): AWS CloudTrail, GCP Cloud Audit Logs, Azure Activity Log, GitHub audit log / token last-used, Stripe/Twilio/SaaS request logs, database logs. Look for use from unknown IPs/regions/user agents, new users/keys/roles, data reads, resource creation, billing spikes. Check what the credential could access (its permissions) as the upper bound | findings list: used / not used / not determinable |
| 4 | If misuse is possible: revoke what the attacker created (keys, roles, tokens, webhooks, OAuth grants, SSH keys), review derived secrets reachable with it (same vault path, same DB), rotate those too | list of additional rotations |
| 5 | **Remove from history** (optional hygiene, see below) | scan of rewritten repo clean |
| 6 | **Notify**: security/owner, affected teams; customers or regulators if personal data was accessed (follow your organisation's breach policy and legal deadlines; check with legal/DPO, not decided here); the provider if they offer abuse handling | notification record |
| 7 | **Prevent recurrence**: pre-commit + CI scan, config loader, store, narrower scope, shorter lifetime; write the post-incident note (root cause, detection time, exposure window, what was accessed) | merged PR + note |

If the secret was only in a local, never-pushed commit: rotating is still safest if it ever left the machine; otherwise rewrite local history and continue.

## Removing it from git history (and what that does not do)

Rewriting history does not un-leak anything: clones, forks, pull-request refs, cached views, CI logs, package registries and archives may retain it, and GitHub states that cached commits can stay reachable by SHA until GitHub Support clears them. Once rotated the old value is harmless, so a rewrite is often optional, and it has costs: changed commit hashes, broken signatures, disrupted open PRs, and colleagues re-contaminating the repo by pushing old clones. Do it for hygiene and scanner noise, after rotation.

### git-filter-repo (preferred over filter-branch; BFG is an alternative)

Per the git-filter-repo manual: work in a fresh clone; `--sensitive-data-removal` (version 2.47+ per GitHub docs) fetches all refs, rewrites, and prints "First Changed Commit(s)" plus orphaned LFS info to help with cleanup.

Executed in a sandbox (git-filter-repo `a40bce548d2c`, gitleaks 8.30.1):

```bash
git clone <REMOTE-URL> repo-clean && cd repo-clean    # fresh clone of the HOSTED repo (origin must be the real remote, not your working copy)
# replacements.txt: one rule per line; literal: is default, regex: and glob: supported
#   literal:THE_LEAKED_VALUE==>***REMOVED***
git filter-repo --sensitive-data-removal --replace-text ../replacements.txt
# or, if the secret lives in a whole file:
git filter-repo --sensitive-data-removal --invert-paths --path .env
git remote -v   # confirm origin is the hosted remote before pushing
gitleaks git --redact --no-banner .                 # expect: no leaks found
git log --all -p | grep -c 'LEAKED_FRAGMENT'        # expect: 0
```

Sandbox result: leaked token replaced by `***REMOVED***` in every commit, gitleaks reported no leaks, occurrences in history 0. Do not keep `replacements.txt` in the repo (it contains the secret); delete it afterwards and keep it out of shell history where possible.

Publishing the rewrite (needs maintainer coordination): `git push --force --mirror origin` overwrites all refs and discards colleagues' pushes made since you started; hosts reject some refs (GitHub: `refs/pull/*`), and branch protection may need temporary relaxation. Tell everyone to stop pushing, then **reclone** (do not rebase onto, merge, or `git pull` old history: that re-introduces the secret; do not re-run your filter commands on their clone, hashes can differ). Verify with `git cat-file -t <first-changed-commit>` (a "fatal" error means gone locally). For hosted forks, cached views and PR refs, contact the host's support (GitHub: only Support can clear cached views and PR references; they handle cases where rotation cannot mitigate the risk). BFG Repo-Cleaner (`--replace-text`, `--delete-files`) is a known alternative; its flags were not verified for this skill, read its current docs.

Also clean the other places: CI logs (delete runs/artifacts), container image layers and registries (delete and rebuild tags), package versions (deprecate/yank), tickets, chat messages, wikis, pastebins.

## Quick scope questions for the incident note

- Which credential, which system, which permissions did it have?
- First exposure time (earliest commit/log/paste) and revocation time.
- Public or private repo; any forks; any CI log retention?
- Provider logs show use in that window: yes / no / not determinable (say which logs were checked and their retention).
- What else did the credential unlock (can it read other secrets)?
- What stops the next one (hook, CI scan, short-lived credentials)?

Hand the data-protection and customer-notification decision to the responsible humans; this skill does not determine legal obligations.

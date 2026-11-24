from __future__ import annotations

SEV = ["critical", "high", "medium", "low", "info"]


def _esc(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render(run: dict, cov: dict) -> str:
    L = [f"# Security audit report (Developer Preview)", "",
         f"- Run: `{run['run_id']}`  |  Profile: **{run['profile']}**  |  Mode: **{run['policy']['mode']}** (no network)",
         f"- Target: `{run['target']['path']}` ({run['target']['files_inspected']} files inspected)",
         f"- Domains: " + ", ".join(f"{d} ({v['confidence']})" for d, v in run["domains"].items()), "",
         "## Coverage (read this first)", "",
         "| Measure | Count |", "|---|---|"]
    for k, label in [("catalog_checks", "Reviewed checks in catalog"), ("applicable", "Applicable checks"),
                     ("executed", "Executed"), ("passed", "Passed"), ("failed", "Failed"),
                     ("inconclusive", "Inconclusive"), ("blocked_or_untested", "Blocked / untested"),
                     ("not_applicable", "Not applicable"), ("deferred_out_of_profile", "Out of profile"),
                     ("verified_vulnerabilities", "Confirmed vulnerabilities (independently validated)"),
                     ("reproduced_candidates", "Candidates (static match, automatically reproduced)"),
                     ("unverified_candidates", "Candidates (not re-verified)"),
                     ("needs_validation", "Candidates needing validation"),
                     ("rejected_candidates", "Rejected candidates")]:
        L.append(f"| {label} | {cov[k]} |")
    L += ["", f"_{cov['note']}_", "", "## Findings", "",
          "> **Developer Preview.** Findings are static-analysis *candidates* unless marked `confirmed`; "
          "`confirmed` requires a recorded independent validation (`security-skills confirm`).", ""]
    fs = [f for f in run["findings"] if f["status"] != "rejected"]
    if not fs:
        L.append("No findings reported by the executed checks. This does not imply the application is secure.")
    for f in sorted(fs, key=lambda x: (SEV.index(x["severity"]), x["id"])):
        v = f.get("verification") or {}
        L += [f"### {f['id']} - {f['title']}", "",
              f"- **Severity:** {f['severity']}  |  **Confidence:** {f['confidence']}  |  **Status:** {f['status']}",
              f"- **Check:** {f['check_id']}  |  **Location:** `{f['location']['path']}:{f['location']['line']}`",
              f"- **Evidence (redacted):** `{_esc(f['evidence'][0]['snippet'])}`",
              f"- **Verification:** {_esc(v.get('rationale', 'not verified - run `security-skills verify`'))}",
              f"- **Expected secure behavior:** {f['expected_secure_behavior']}",
              f"- **Remediation:** {f['remediation']}", ""]
    L += ["## Untested checks", "", "| Check | Domain | Status | Reason |", "|---|---|---|---|"]
    for r in run["executions"]:
        if r["status"] in ("blocked", "planned"):
            L.append(f"| {r['check_id']} | {r['domain']} | {r['status']} | {_esc(r['reason'])} |")
    L += ["", "## Not applicable / out of profile", "",
          f"{cov['not_applicable']} checks not applicable and {cov['deferred_out_of_profile']} outside the selected profile "
          "(see `results.json` for each reason).", ""]
    return "\n".join(L)

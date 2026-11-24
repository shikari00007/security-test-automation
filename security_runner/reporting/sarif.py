from __future__ import annotations

import json

from .. import __version__

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SEC = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}


def render(run: dict, cov: dict) -> str:
    findings = [f for f in run.get("findings", []) if f.get("status") != "rejected"]
    rules, seen = [], {}
    for f in findings:
        if f["check_id"] in seen:
            continue
        seen[f["check_id"]] = len(rules)
        tags = [f["domain"]] + [f"external/cwe/{c.lower()}" for c in f["standards"].get("cwe", [])]
        rules.append({"id": f["check_id"], "name": f["title"], "shortDescription": {"text": f["title"]},
                      "help": {"text": f["remediation"]}, "defaultConfiguration": {"level": LEVEL[f["severity"]]},
                      "properties": {"tags": tags, "security-severity": SEC[f["severity"]]}})
    results = []
    for f in findings:
        loc = f["location"]
        results.append({
            "ruleId": f["check_id"], "ruleIndex": seen[f["check_id"]], "level": LEVEL[f["severity"]],
            "message": {"text": f"{f['title']}: {f['evidence'][0]['detail']}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc["path"]},
                                                  "region": {"startLine": loc["line"],
                                                             "snippet": {"text": f["evidence"][0]["snippet"]}}}}],
            "partialFingerprints": {"securitySkills/v1": f["id"]},
            "properties": {"verdict": f["status"], "confidence": f["confidence"]}})
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "security-skills", "version": __version__,
                                         "informationUri": "https://github.com/shikari00007/security-test-automation",
                                         "rules": rules}},
                     "results": results,
                     "properties": {"run_id": run["run_id"], "coverage": cov,
                                    "note": "Unverified candidates are included with properties.verdict != confirmed."}}]}
    return json.dumps(doc, indent=2) + "\n"

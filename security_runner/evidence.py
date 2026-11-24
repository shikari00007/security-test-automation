"""Redaction, hashing and the tamper-evident run manifest.

Evidence is only trusted after ``verification.verify_run`` re-derives it from the target
files. A non-empty evidence string is never sufficient.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re

SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"), "[REDACTED-PRIVATE-KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})\b"), "[REDACTED-GITHUB-TOKEN]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED-SLACK-TOKEN]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "[REDACTED-API-KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"), "[REDACTED-JWT]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret)[\"']?\s*[:=]\s*[\"'])([^\"']{3,})([\"'])"),
     r"\1[REDACTED]\3"),
    (re.compile(r"(?i)(://[^/\s:@]+:)([^@\s/]{3,})(@)"), r"\1[REDACTED]\3"),
]


def redact(text: str, limit: int = 240) -> str:
    for rx, rep in SECRET_PATTERNS:
        text = rx.sub(rep, text)
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "...[truncated]"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def line_mac(run_id: str, raw_line: str) -> str:
    """Salted hash of the raw line: lets the verifier confirm the evidence without
    storing the (possibly secret) line text."""
    return hashlib.sha256(f"{run_id}\x00{raw_line.rstrip()}".encode("utf-8")).hexdigest()


def record_hash(record: dict, prev: str) -> str:
    body = {k: v for k, v in record.items() if k != "record_hash"}
    return sha256_bytes(canonical_json(body) + prev.encode())


def seal(run: dict, key: bytes | None = None) -> dict:
    """Chain execution records and compute the manifest digest (+ optional HMAC)."""
    prev = "0" * 64
    for rec in run["executions"]:
        rec["prev_hash"] = prev
        rec["record_hash"] = record_hash(rec, prev)
        prev = rec["record_hash"]
    body = {k: v for k, v in run.items() if k not in ("manifest_sha256", "signature")}
    run["manifest_sha256"] = sha256_bytes(canonical_json(body))
    run.pop("signature", None)
    if key:
        run["signature"] = hmac.new(key, run["manifest_sha256"].encode(), "sha256").hexdigest()
    return run

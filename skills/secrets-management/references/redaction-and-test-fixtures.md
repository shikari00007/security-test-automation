# Redaction helpers and test fixtures

Both helpers were executed with tests (Python: 4 pytest tests; JS: 4 `node --test` tests). See [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md). They are a safety net, not a substitute for never logging secrets: key- and pattern-based redaction misses unknown formats.

## Where to apply

- Logging handlers (attach to handlers so every logger is covered), error reporters (Sentry-style `before_send`/`beforeSend`), HTTP client debug logs, exception messages, API error bodies.
- Never log: `Authorization`, `Cookie`/`Set-Cookie` headers, request bodies of login/payment endpoints, full config objects, connection strings, environment dumps.
- Return generic errors to clients; log details server-side after redaction.

## Python (stdlib only) - redact.py

```python
"""Redaction helper: scrub secrets from log records and error text (stdlib only)."""
import logging
import re
from typing import Any

REDACTED = "[REDACTED]"
SENSITIVE_KEYS = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|set-cookie|private[_-]?key|credential|session)",
    re.IGNORECASE,
)
# Value patterns: well-known prefixes plus Bearer/Basic headers and URL userinfo.
VALUE_PATTERNS = [
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)"),  # user:pass@ in URLs
    re.compile(r"\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT shape
    # key=value, key: value and JSON "key": "value"; the key may carry a prefix (access_token, DB_PASSWORD)
    re.compile(r'''(?i)([\w.-]*(?:password|passwd|secret|token|api[_-]?key))(["']?\s*[=:]\s*)(["']?)([^&\s"',;}]+)'''),
]


def redact_text(text: str) -> str:
    for pat in VALUE_PATTERNS:
        if pat.groups >= 4:
            text = pat.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}", text)
        else:
            text = pat.sub(REDACTED, text)
    return text


def redact(obj: Any, _depth: int = 0) -> Any:
    """Return a copy of obj (dict/list/str) with sensitive keys and values masked."""
    if _depth > 20:
        return REDACTED
    if isinstance(obj, dict):
        return {
            k: REDACTED if SENSITIVE_KEYS.search(str(k)) else redact(v, _depth + 1)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [redact(v, _depth + 1) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


class RedactingFilter(logging.Filter):
    """Attach to handlers (not loggers) so records from every logger are scrubbed."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = ()
        if record.exc_info:
            record.exc_text = redact_text(logging.Formatter().formatException(record.exc_info))
            record.exc_info = None
        return True
```

Use: `handler = logging.StreamHandler(); handler.addFilter(RedactingFilter()); logging.getLogger().addHandler(handler)`.

Test (passes):

```python
import io, logging
from redact import redact, redact_text, RedactingFilter, REDACTED

FAKE_GH = "ghp_" + "F" * 36                       # assembled at runtime, obviously fake
FAKE_JWT = ".".join(["eyJ" + "x" * 10, "y" * 12, "z" * 12])

def test_dict_keys_and_nested():
    out = redact({"user": "ann", "password": "hunter2", "h": {"Authorization": "Bearer abcdefgh12345"}})
    assert out == {"user": "ann", "password": REDACTED, "h": {"Authorization": REDACTED}}

def test_value_patterns():
    for s in (FAKE_GH, FAKE_JWT, "Bearer abcdefgh12345", "postgres://app:s3cr3t@db/x", "x?token=abc123&a=1"):
        assert "s3cr3t" not in redact_text(s) and REDACTED in redact_text(s), s
    assert redact_text("x?token=abc123&a=1") == "x?token=[REDACTED]&a=1"
    assert redact_text("plain message") == "plain message"
    assert redact_text("token_count=5") == "token_count=5"

def test_prefixed_keys_and_other_shapes():
    for s in ("access_token=abc12345", "client_secret=abc12345", "DB_PASSWORD=hunter2",
              "password: hunter2", '{"password": "hunter2"}', '{"password":"hunter2"}'):
        out = redact_text(s)
        assert REDACTED in out and "abc12345" not in out and "hunter2" not in out, (s, out)

def test_logging_filter_incl_exception():
    buf = io.StringIO(); h = logging.StreamHandler(buf); h.addFilter(RedactingFilter())
    log = logging.getLogger("t"); log.addHandler(h); log.setLevel(logging.INFO)
    log.info("calling with %s", FAKE_GH)
    try:
        raise RuntimeError("bad url postgres://app:s3cr3t@db/x")
    except RuntimeError:
        log.exception("failed")
    assert FAKE_GH not in buf.getvalue() and "s3cr3t" not in buf.getvalue()
```

## JavaScript (ESM, no dependencies) - redact.mjs

```js
export const REDACTED = "[REDACTED]";
const SENSITIVE_KEYS =
  /(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|set-cookie|private[_-]?key|credential|session)/i;
const VALUE_PATTERNS = [
  [/\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, REDACTED],
  [/(?<=:\/\/)[^/\s:@]+:[^/\s@]+(?=@)/g, REDACTED],
  [/\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{20,}\b/g, REDACTED],
  [/\bAKIA[0-9A-Z]{16}\b/g, REDACTED],
  [/\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g, REDACTED],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, REDACTED],
  [/([\w.-]*(?:password|passwd|secret|token|api[_-]?key))(["']?\s*[=:]\s*)(["']?)([^&\s"',;}]+)/gi, `$1$2$3${REDACTED}`],
];

export function redactText(text) {
  return VALUE_PATTERNS.reduce((t, [re, rep]) => t.replace(re, rep), String(text));
}

export function redact(value, depth = 0) {
  if (depth > 20) return REDACTED;
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value instanceof Error) {
    const e = new Error(redactText(value.message));
    e.name = value.name;
    e.stack = redactText(value.stack ?? "");
    return e;
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k, SENSITIVE_KEYS.test(k) ? REDACTED : redact(v, depth + 1)]),
    );
  }
  return value;
}
```

Test (`node --test`, passes):

```js
import test from "node:test";
import assert from "node:assert/strict";
import { redact, redactText, REDACTED } from "./redact.mjs";
const FAKE_GH = "ghp_" + "F".repeat(36);
test("keys", () => {
  assert.deepEqual(redact({ user: "ann", password: "hunter2", h: { Authorization: "Bearer abcdefgh12345" } }),
    { user: "ann", password: REDACTED, h: { Authorization: REDACTED } });
});
test("values", () => {
  for (const s of [FAKE_GH, "Bearer abcdefgh12345", "postgres://app:s3cr3t@db/x"]) {
    assert.ok(!redactText(s).includes("s3cr3t") && redactText(s).includes(REDACTED), s);
  }
  assert.equal(redactText("x?token=abc123&a=1"), "x?token=[REDACTED]&a=1");
  assert.equal(redactText("token_count=5"), "token_count=5");
});
test("prefixed keys and other shapes", () => {
  for (const s of ["access_token=abc12345", "client_secret=abc12345", "DB_PASSWORD=hunter2",
    "password: hunter2", '{"password": "hunter2"}', '{"password":"hunter2"}']) {
    const out = redactText(s);
    assert.ok(out.includes(REDACTED) && !/abc12345|hunter2/.test(out), `${s} -> ${out}`);
  }
});
test("error", () => {
  const e = redact(new Error("db postgres://app:s3cr3t@db/x"));
  assert.ok(!e.message.includes("s3cr3t") && !e.stack.includes("s3cr3t"));
});
```

For pino use built-in `redact: { paths: ["req.headers.authorization", "req.headers.cookie", "*.password"], censor: "[REDACTED]" }` (option shape from pino docs; not executed here).

Known limits: URL passwords containing `@` or `/` are only partly redacted (executed: `postgres://u:p@ss@db/x` became `postgres://[REDACTED]@ss@db/x`); custom-format or short secrets without a key name next to them are not caught; add your own patterns. Regexes are linear-pattern and not tuned for huge inputs.

## Test fixtures that never contain real credentials

Rules:
1. Synthetic and obviously fake: `FAKE-not-a-real-key`, `test-secret-do-not-use`, `postgres://user:fakepw@localhost/db`.
2. Never copy a value from production, staging or your own `.env` into a test, snapshot, HAR file, VCR cassette or mock response. Scrub recorded HTTP before committing.
3. Generate token-shaped values at runtime when the code under test validates the format: `"ghp_" + "F" * 36`. Executed against gitleaks 8.30.1 default rules with these results:

| Fixture value | Scanner result |
|---|---|
| `AKIAIOSFODNN7EXAMPLE` (AWS documentation key) | not flagged |
| `ghp_` + 36 repeated `F` | not flagged (low entropy) |
| `ghp_` + 36 random alphanumerics | flagged (looks real) |
| `sk_test_` + 24 alphanumerics (Stripe test-key shape, built at runtime, never a literal in the repo) | flagged |
| `FAKE-not-a-real-key`, `test-secret-do-not-use`, `postgres://user:fakepw@localhost/db` | not flagged |

   Results depend on rules and version; re-run the scan after adding fixtures. A "test-mode" provider key (like `sk_test_...`) is still a real credential for a sandbox account: do not commit it.
4. Prefer placeholders that fail loudly if reached over the network (`example.invalid` hosts) and mocks over live calls.
5. If a fixture must match a scanner, allowlist only that path and rule in `.gitleaks.toml` with a description (leak-prevention-scanning.md), not the whole `tests/` tree.
6. Test the secret handling itself: missing config fails fast, secrets are masked in `repr`/JSON, logs are redacted, error responses carry no secrets.

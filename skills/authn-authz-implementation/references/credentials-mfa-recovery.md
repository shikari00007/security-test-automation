# Credentials, rate limiting, MFA and account recovery

Editions: OWASP Password Storage Cheat Sheet, Forgot Password Cheat Sheet (live pages, fetched 2026-11-25), OWASP ASVS 5.0.0 (May 2025) V6, W3C WebAuthn Level 2 (Recommendation) and Level 3 (Candidate Recommendation Snapshot 26 May 2026). See [VERIFICATION-NOTES](VERIFICATION-NOTES.md).

## 1. Password hashing: choose and parameterise

| Situation | Use | Parameters (OWASP Password Storage Cheat Sheet) |
|---|---|---|
| New system, library available | **Argon2id** | minimum m=19456 KiB (19 MiB), t=2, p=1. Equivalent alternatives: m=47104,t=1 / m=12288,t=3 / m=9216,t=4 / m=7168,t=5 (all p=1) |
| No Argon2id (stdlib only) | **scrypt** | r=8 and one of: N=2^17,p=1 / N=2^16,p=2 / N=2^15,p=3 / N=2^14,p=5 / N=2^13,p=10 |
| FIPS-140 required | PBKDF2 | HMAC-SHA256 600,000 iterations; HMAC-SHA512 220,000 |
| Legacy only | bcrypt | work factor >= 10, and enforce a 72-byte maximum input |

Rules:
- These are floors. Benchmark on production hardware; the sheet aims for under one second per hash. Re-benchmark yearly.
- Per-password random salt (libraries do this). A pepper is optional defense in depth: keep it outside the database (vault/HSM); if it leaks, affected users must reset.
- Never SHA-256/MD5/unsalted anything, never encryption instead of hashing, never log passwords or hashes.
- bcrypt truncates at 72 bytes (verified: bcrypt 5.0.0 raises `ValueError` above 72 bytes). Do not "fix" with plain `bcrypt(sha512(pw))`; the sheet calls that dangerous (password shucking, NUL bytes). Prefer migrating to Argon2id; on login, rehash with the new algorithm when verification succeeds.
- ASVS 5.0 V6.2: min 8 chars, 15 recommended (6.2.1); accept 64+ chars (6.2.9); no composition rules (6.2.5); verify as received with no truncation or case change (6.2.8); no forced periodic rotation (6.2.10); check against the top 3000 common passwords at least (6.2.4) and ideally breached sets (6.2.12); allow paste and password managers (6.2.7). Keep an explicit upper bound (for example 128 characters) so a 10 MB "password" cannot become a CPU/memory DoS.
- ASVS 5.0 has no password-hashing requirement of its own; it defers to the cheat sheet.

### Stdlib scrypt with constant-time compare (executed, see notes)

Cost warning: scrypt at N=2^17 takes about 0.4 s and 128 MiB per hash, so concurrent logins are a memory/CPU denial-of-service vector. Rate-limit before hashing and cap concurrent hash operations (semaphore or worker pool).

```python
# file: hashing.py
import base64
import hashlib
import hmac
import os

N, R, P = 2**17, 8, 1            # OWASP scrypt option: 128 MiB, p=1
MAXMEM = 256 * 1024 * 1024       # hashlib default (32 MiB) is too low for N=2**17
MAX_PASSWORD_CHARS = 128


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _kdf(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=MAXMEM, dklen=32)


def hash_password(password: str) -> str:
    if not 1 <= len(password) <= MAX_PASSWORD_CHARS:
        raise ValueError("password length out of range")
    salt = os.urandom(16)
    return f"scrypt${N}${R}${P}${_b64(salt)}${_b64(_kdf(password, salt, N, R, P))}"


def verify_password(stored: str, password: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt" or len(password) > MAX_PASSWORD_CHARS:
            return False
        expected = base64.b64decode(digest)
        got = _kdf(password, base64.b64decode(salt), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, expected)       # constant-time


def needs_rehash(stored: str) -> bool:
    parts = stored.split("$")
    return parts[:4] != ["scrypt", str(N), str(R), str(P)]


DUMMY_HASH = hash_password("dummy-password-for-timing")


def authenticate(users: dict, username: str, password: str):
    """Return the user record or None. Same work and same result shape for
    unknown user and wrong password (no user enumeration by timing/message)."""
    record = users.get(username)
    stored = record["password_hash"] if record else DUMMY_HASH
    ok = verify_password(stored, password)
    return record if (record and ok) else None
```

```python
# file: test_hashing.py
import pytest
import hashing


def test_roundtrip_and_wrong_password():
    h = hashing.hash_password("correct horse battery staple")
    assert hashing.verify_password(h, "correct horse battery staple")
    assert not hashing.verify_password(h, "correct horse battery stapl3")


def test_salts_are_unique_and_params_recorded():
    a, b = hashing.hash_password("same"), hashing.hash_password("same")
    assert a != b
    assert a.startswith("scrypt$131072$8$1$")
    assert not hashing.needs_rehash(a)
    assert hashing.needs_rehash("scrypt$16384$8$1$AA==$AA==")


def test_garbage_and_overlong_input_rejected_not_raised():
    assert not hashing.verify_password("not-a-hash", "x")
    h = hashing.hash_password("x")
    assert not hashing.verify_password(h, "x" * 10_000)
    with pytest.raises(ValueError):
        hashing.hash_password("")


def test_unknown_user_and_wrong_password_look_the_same():
    users = {"alice": {"password_hash": hashing.hash_password("pw-alice-1")}}
    assert hashing.authenticate(users, "alice", "pw-alice-1") is users["alice"]
    assert hashing.authenticate(users, "alice", "nope") is None
    assert hashing.authenticate(users, "mallory", "nope") is None


def test_argon2id_library_api_with_owasp_minimum():
    from argon2 import PasswordHasher
    ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
    h = ph.hash("pw")
    assert h.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert ph.verify(h, "pw")
    assert not ph.check_needs_rehash(h)
    stronger = PasswordHasher(time_cost=3, memory_cost=19456, parallelism=1)
    assert stronger.check_needs_rehash(h)
```

Argon2 (argon2-cffi 25.1.0): `PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)`; `.verify(hash, pw)` raises `argon2.exceptions.VerifyMismatchError` on mismatch (the test above only exercises the success path and `check_needs_rehash`); call `check_needs_rehash` after a successful login and store the new hash. The library's own defaults (m=65536, t=3, p=4) already exceed the OWASP minimum.

## 2. Rate limiting and lockout (ASVS 6.1.1, 6.3.1)

Document and implement; the design question is "how do I stop guessing without letting an attacker lock out the victim".

| Control | Do | Do not |
|---|---|---|
| Per-account counter | Exponential delay or temporary soft lock (for example 5 failures then 1, 2, 4... minutes) on the *login attempt*, success still possible with correct password + not locked-out device | Permanent hard lock after N failures (turns brute force into account DoS; ASVS 6.1.1 asks you to document how malicious lockout is prevented) |
| Per-IP / per-device counter | Separate bucket, higher threshold, shared across usernames (catches spraying) | Trust `X-Forwarded-For` from the client; take client IP only from your trusted proxy hop |
| Credential stuffing | Breached-password check at set time (6.2.12), step-up/MFA on anomalous login, notify user (6.3.5, L3) | CAPTCHA as the only control |
| OTP / recovery code endpoints | Rate-limit per account and per code issued (6.6.3); invalidate code after N wrong tries | Allow unlimited attempts on a 6-digit code |
| Reset-request endpoint | Limit per account and per IP; never change account state until a valid token is presented | Lock account because someone requested resets |
| Storage | Shared store (Redis/DB), not per-process memory, when more than one worker | In-process dict behind 4 gunicorn workers (limit is 4x, and resets on deploy) |

Library entry points (verify the installed version): `slowapi` (Starlette/FastAPI), `Flask-Limiter`, `django-axes` or DRF throttles, `express-rate-limit`. Tests assert the 429/lock behaviour with an injected clock, not `sleep`.

## 3. MFA and WebAuthn basics

- ASVS 5.0: MFA or combined single factors required at L2 (6.3.3); at L3 one factor must be hardware-based and phishing-resistant. SMS/PSTN OTP only to previously validated numbers and with stronger alternatives offered (6.6.1), and not at L3. Email is not an authentication factor at L3 (6.3.6). Codes: single use (6.5.1), CSPRNG (6.5.3), >= 20 bits entropy (6.5.4), out-of-band codes live at most 10 minutes and TOTP at most 30 seconds (6.5.5 as worded in ASVS 5.0). Rate-limit push prompts (6.6.4, L3).
- TOTP seeds: store encrypted at rest (reversible, they must be recomputed), never log them; validate against server time (6.5.8); reject reuse of the same code within its window.
- Recovery codes: show once, store hashed with the password algorithm, single use.
- Re-authenticate before changing email, phone or MFA settings (ASVS 7.5.1), and offer to end other sessions after a factor change (7.4.3).
- **WebAuthn/passkeys**: use a maintained server library (for example `webauthn` / `py_webauthn` for Python, `@simplewebauthn/server` for Node; confirm the current API in its docs before coding, not from memory). Server responsibilities that the library will not do for you: generate a fresh random challenge per ceremony (ASVS 6.7.2 asks >= 64 bits), store it server-side bound to the session and consume it once, pin `rpId` and expected origin(s) to your exact values, require user verification where you treat the passkey as a sole factor, store credential id + public key + signature counter per user, and allow revoking any credential (6.5.6, L3). WebAuthn Level 2 is the W3C Recommendation; Level 3 is a Candidate Recommendation Snapshot as of 2026-05-26.

## 4. Account recovery (OWASP Forgot Password Cheat Sheet; ASVS 6.4.x)

1. Same response text, status and (roughly) timing for existing and unknown accounts; send mail asynchronously (ASVS 6.3.8 L3).
2. Token: CSPRNG, long (at least 128 bits), stored hashed, bound to one user, single use, short expiry (minutes to an hour), invalidated by any newer request or by a password change.
3. Build the link from configured base URL, never from the `Host` header. Serve over HTTPS; set `Referrer-Policy: no-referrer` on the reset page.
4. Do not auto-login after reset; require normal login (with MFA). The reset flow must not bypass MFA (ASVS 6.4.3). Lost-MFA recovery needs identity proofing equal to enrolment (6.4.4).
5. After reset: notify the user by email (no password in it), end all other sessions (ASVS 7.4.3), invalidate outstanding reset tokens.
6. No security questions or hints (ASVS 6.4.2). Admin-initiated resets send a reset link; admins never choose the password (6.4.6, L3).

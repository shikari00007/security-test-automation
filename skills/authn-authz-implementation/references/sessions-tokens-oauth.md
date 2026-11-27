# Sessions, tokens (JWT vs opaque) and OAuth 2.0 / OIDC

Editions: OWASP Session Management Cheat Sheet (live page, fetched 2026-11-25); OWASP ASVS 5.0.0 (May 2025) V3.3, V7, V9, V10; RFC 9700 (OAuth 2.0 Security BCP, BCP 240, January 2025); RFC 7636 (PKCE); RFC 8725 (JWT BCP, BCP 225); RFC 7519 (JWT); RFC 9068 (JWT access tokens); RFC 9207 (issuer identification); RFC 9449 (DPoP); RFC 8252 (native apps). Evidence: [VERIFICATION-NOTES](VERIFICATION-NOTES.md).

## 1. Server-side sessions (default for first-party web apps)

| Requirement | Source | Implementation |
|---|---|---|
| Unguessable id from a CSPRNG, >= 128 bits | ASVS 7.2.3; cheat sheet (64 bits minimum, 128+ recommended) | `secrets.token_urlsafe(32)` (256 bits) / `crypto.randomBytes(32)`; never user-derived or sequential |
| Store only a hash of the id server-side | defense in depth | key the store by `sha256(sid)` so a DB read does not yield live cookies |
| New id on every authentication and privilege change; old one destroyed | ASVS 7.2.4; cheat sheet "Renewal" | `create(user, old_sid=...)` below |
| Idle and absolute timeouts enforced server-side | ASVS 7.3.1, 7.3.2; cheat sheet: idle 2-5 min high-value, 15-30 min low-risk; absolute 4-8 h for all-day apps | numbers are a risk decision: record them in `.agents/security-project-context.md` or an ADR |
| Logout destroys the server record; account disable ends all sessions | ASVS 7.4.1, 7.4.2 | `destroy`, `destroy_all_for_user` |
| After password/MFA change or recovery: end other sessions | ASVS 7.4.3 | call `destroy_all_for_user(except=current)` |
| Re-authenticate before changing email/phone/MFA | ASVS 7.5.1 | recent-auth timestamp check |

Cookie attributes (ASVS 3.3.1-3.3.4; cheat sheet example `__Host-SessionID=<v>; Secure; HttpOnly; SameSite=Strict; Path=/`):
`Secure`, `HttpOnly`, explicit `SameSite` (Strict preferred, Lax when you need inbound top-level links; never rely on browser default; never `None` unless cross-site is required), no `Domain` attribute, `Path=/`, `__Host-` name prefix (requires Secure, Path=/, no Domain). SameSite is defence in depth, not a substitute for CSRF tokens on state-changing cookie-authenticated requests (ASVS 3.5.x).

```python
# file: session_store.py
import hashlib
import secrets
import time

SESSION_COOKIE = {            # pass to your framework's set_cookie
    "key": "__Host-sid", "httponly": True, "secure": True,
    "samesite": "lax", "path": "/",   # no domain= on purpose
}


def _key(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


class SessionStore:
    def __init__(self, idle_seconds=1800, absolute_seconds=8 * 3600, clock=time.monotonic):
        self.idle, self.absolute, self.clock = idle_seconds, absolute_seconds, clock
        self._data = {}

    def create(self, user_id, old_sid=None, **attrs) -> str:
        """Always issue a NEW id (fixation defence); destroy the pre-login id."""
        if {"created", "seen"} & attrs.keys():
            raise ValueError("reserved session attribute")
        if old_sid:
            self.destroy(old_sid)
        sid = secrets.token_urlsafe(32)
        now = self.clock()
        self._data[_key(sid)] = {"user_id": user_id, "created": now, "seen": now, **attrs}
        return sid

    def get(self, sid):
        rec = self._data.get(_key(sid)) if sid else None
        if rec is None:
            return None
        now = self.clock()
        if now - rec["seen"] > self.idle or now - rec["created"] > self.absolute:
            self.destroy(sid)
            return None
        rec["seen"] = now
        return rec

    def destroy(self, sid):
        self._data.pop(_key(sid), None)

    def destroy_all_for_user(self, user_id, except_sid=None):
        keep = _key(except_sid) if except_sid else None
        for k in [k for k, v in self._data.items() if v["user_id"] == user_id and k != keep]:
            del self._data[k]
```

```python
# file: test_session_store.py
from session_store import SessionStore, SESSION_COOKIE


class Clock:
    t = 0.0
    def __call__(self):
        return self.t


def test_login_rotates_id_and_old_id_dies():
    s = SessionStore()
    pre = s.create(None)                       # anonymous session
    post = s.create("alice", old_sid=pre)      # login
    assert post != pre
    assert s.get(pre) is None and s.get(post)["user_id"] == "alice"


def test_logout_invalidates_server_side():
    s = SessionStore()
    sid = s.create("alice")
    s.destroy(sid)
    assert s.get(sid) is None


def test_idle_and_absolute_timeouts():
    c = Clock()
    s = SessionStore(idle_seconds=100, absolute_seconds=250, clock=c)
    sid = s.create("alice")
    c.t = 90;  assert s.get(sid)           # activity keeps it alive
    c.t = 180; assert s.get(sid)
    c.t = 260; assert s.get(sid) is None   # absolute cap beats activity
    sid2 = s.create("alice")
    c.t = 260 + 101
    assert s.get(sid2) is None             # idle


def test_password_change_ends_other_sessions_keeps_current():
    s = SessionStore()
    a, b = s.create("alice"), s.create("alice")
    s.destroy_all_for_user("alice", except_sid=a)
    assert s.get(a) and s.get(b) is None


def test_reserved_attributes_cannot_be_overwritten():
    import pytest
    with pytest.raises(ValueError):
        SessionStore().create("alice", created=10**12)


def test_store_keys_are_hashed_and_cookie_flags():
    s = SessionStore()
    sid = s.create("alice")
    assert sid not in s._data
    assert SESSION_COOKIE["secure"] and SESSION_COOKIE["httponly"]
    assert SESSION_COOKIE["key"].startswith("__Host-") and "domain" not in SESSION_COOKIE
```

## 2. Opaque token vs JWT: decision

| Question | Opaque (random id looked up server-side) | Self-contained JWT |
|---|---|---|
| Need instant revocation / logout / role change (ASVS 8.3.2, 7.4.1)? | Yes: delete the row | Hard: needs denylist, per-user cutoff time or key rotation (ASVS 7.4.1) |
| Many independent resource servers verifying offline? | Needs introspection (RFC 7662) | Good fit (verify with issuer JWKS) |
| Browser first-party app, one backend | **Prefer this** (cookie session) | Adds risk, no benefit |
| Mobile/SPA calling your own API | Opaque or short-lived JWT behind BFF | Short-lived (minutes) access token + rotating refresh token |
| Service-to-service | Either; mTLS or client-credentials with short-lived JWT | Short-lived, audience-restricted |

Default: cookie session or opaque token unless you have a concrete cross-service verification need.

## 3. JWT verification rules (RFC 8725; ASVS 5.0 V9)

- Verify the signature before reading any claim (ASVS 9.1.1). Allowlist algorithms per verifier, never trust the token's `alg` to choose behaviour; `none` is never allowed (9.1.2; RFC 8725 sec 3.1, 3.2). Do not mix HMAC and RSA/EC keys under one verifier (key confusion).
- Keys come only from pre-configured trusted sources for the issuer; reject or allowlist `jku`, `x5u`, `jwk` headers (9.1.3). Look up the key by `kid` in your own keyset and take the algorithm from the key record.
- Require `exp` (RFC 8725 / policy) and check `nbf`/`exp` (ASVS 9.2.1, which applies when a validity span is present); require and check `iss` (RFC 8725 sec 3.8) and `aud` against an allowlist of values for this service (9.2.3; RFC 8725 sec 3.9). Small clock leeway only (30-60 s).
- Check token *type/purpose* (9.2.2; RFC 8725 sec 3.11, 3.12): do not accept an ID token as an access token; RFC 9068 access tokens use `typ: at+jwt`. The minimal verifier below checks `typ` only when you pass `typ=`; with a library pass the expected type explicitly.
- Authorization data (roles, tenant) in a JWT is stale until expiry; for sensitive decisions re-read from your DB (ASVS 8.3.2).
- Key rotation: publish multiple `kid`s, sign with the newest, keep the previous one verifiable until all tokens signed with it have expired, then remove it. Symmetric secrets need >= 256 bits of randomness (RFC 8725 sec 3.5).
- Storage: browser JS-readable storage (localStorage) is exposed to XSS. Prefer a BFF holding tokens server-side (ASVS 10.1.1) or `HttpOnly` cookies with CSRF protection. Never put tokens in URLs.
- Do not hand-roll in production. The verifier below is minimal, to prove the rules; use PyJWT / `jose` / `jsonwebtoken` with explicit algorithms.

```python
# file: jwt_verify.py
import base64
import hashlib
import hmac
import json
import math
import re
import time


class InvalidToken(Exception):
    pass


def _b64d(part: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", part):          # strict: one string form per token
        raise InvalidToken("bad base64url")
    try:
        return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    except Exception as exc:
        raise InvalidToken("bad base64url") from exc


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign_hs256(claims: dict, key: bytes, kid: str) -> str:   # test helper / issuer side
    head = b64e(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    body = b64e(json.dumps(claims).encode())
    sig = hmac.new(key, f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64e(sig)}"


FORBIDDEN_HEADERS = {"jku", "x5u", "jwk", "x5c", "crit"}


def verify(token: str, keyset: dict, *, issuer: str, audience: str, leeway: int = 30, now=None,
           typ: str | None = None) -> dict:
    """keyset: {kid: (alg, key_bytes)}. Algorithm comes from OUR key record, not the token.
    typ: expected JOSE `typ` header (e.g. "at+jwt"); pass it so an ID token is not accepted as an access token."""
    now = time.time() if now is None else now
    try:
        head_b64, body_b64, sig_b64 = token.split(".")
        header = json.loads(_b64d(head_b64))
    except (ValueError, InvalidToken) as exc:
        raise InvalidToken("malformed") from exc
    if not isinstance(header, dict) or FORBIDDEN_HEADERS & header.keys():
        raise InvalidToken("forbidden header")
    kid = header.get("kid")
    if not isinstance(kid, str):                        # attacker-controlled, pre-signature: never hash a list/dict
        raise InvalidToken("bad kid")
    entry = keyset.get(kid)
    if entry is None:
        raise InvalidToken("unknown kid")
    alg, key = entry
    if alg != "HS256" or header.get("alg") != alg:      # allowlist + no 'none'
        raise InvalidToken("algorithm not allowed")
    if typ is not None and header.get("typ") != typ:
        raise InvalidToken("wrong token type")
    expected = hmac.new(key, f"{head_b64}.{body_b64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, _b64d(sig_b64)):
        raise InvalidToken("bad signature")
    try:
        claims = json.loads(_b64d(body_b64))
    except ValueError as exc:
        raise InvalidToken("bad payload") from exc
    if not isinstance(claims, dict):
        raise InvalidToken("bad payload")
    for required in ("exp", "iss", "aud", "sub"):
        if required not in claims:
            raise InvalidToken(f"missing {required}")
    for name in ("exp", "nbf"):                         # a signed but non-numeric/NaN exp must not pass
        if name in claims and (isinstance(claims[name], bool) or not isinstance(claims[name], (int, float))
                               or not math.isfinite(claims[name])):
            raise InvalidToken(f"bad {name}")
    if now > claims["exp"] + leeway:
        raise InvalidToken("expired")
    if "nbf" in claims and now < claims["nbf"] - leeway:
        raise InvalidToken("not yet valid")
    if claims["iss"] != issuer:
        raise InvalidToken("wrong issuer")
    aud = claims["aud"] if isinstance(claims["aud"], list) else [claims["aud"]]
    if audience not in aud:
        raise InvalidToken("wrong audience")
    return claims
```

```python
# file: test_jwt_verify.py
import json
import time

import pytest

import jwt_verify as jv

K1, K2 = b"k" * 32, b"j" * 32
KEYS = {"k1": ("HS256", K1)}
ISS, AUD = "https://issuer.example", "orders-api"


def claims(**kw):
    base = {"sub": "u1", "iss": ISS, "aud": AUD, "exp": time.time() + 300}
    base.update(kw)
    return base


def tok(**kw):
    return jv.sign_hs256(claims(**kw), K1, "k1")


def verify(t, keys=KEYS):
    return jv.verify(t, keys, issuer=ISS, audience=AUD)


def test_valid_token_accepted():
    assert verify(tok())["sub"] == "u1"


def test_alg_none_rejected():
    head = jv.b64e(json.dumps({"alg": "none", "typ": "JWT", "kid": "k1"}).encode())
    body = jv.b64e(json.dumps(claims()).encode())
    for forged in (f"{head}.{body}.", f"{head}.{body}.AAAA"):
        with pytest.raises(jv.InvalidToken):
            verify(forged)


def test_alg_confusion_header_rejected():
    good = tok()
    h, b, s = good.split(".")
    head = jv.b64e(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k1"}).encode())
    with pytest.raises(jv.InvalidToken):
        verify(f"{head}.{b}.{s}")


def test_tampered_payload_rejected():
    h, b, s = tok().split(".")
    evil = jv.b64e(json.dumps(claims(sub="admin")).encode())
    with pytest.raises(jv.InvalidToken, match="bad signature"):
        verify(f"{h}.{evil}.{s}")


@pytest.mark.parametrize("kw,msg", [
    ({"exp": time.time() - 3600}, "expired"),
    ({"aud": "other-api"}, "wrong audience"),
    ({"iss": "https://evil.example"}, "wrong issuer"),
    ({"nbf": time.time() + 3600}, "not yet valid"),
])
def test_claim_checks(kw, msg):
    with pytest.raises(jv.InvalidToken, match=msg):
        verify(tok(**kw))


def test_missing_exp_rejected():
    c = claims(); del c["exp"]
    with pytest.raises(jv.InvalidToken, match="missing exp"):
        verify(jv.sign_hs256(c, K1, "k1"))


def test_untrusted_key_headers_rejected():
    head = jv.b64e(json.dumps({"alg": "HS256", "kid": "k1", "jku": "https://evil.example/jwks"}).encode())
    body = jv.b64e(json.dumps(claims()).encode())
    with pytest.raises(jv.InvalidToken, match="forbidden header"):
        verify(f"{head}.{body}.AAAA")


def test_key_rotation_overlap_then_retire():
    old = jv.sign_hs256(claims(), K1, "k1")
    new = jv.sign_hs256(claims(), K2, "k2")
    both = {"k1": ("HS256", K1), "k2": ("HS256", K2)}
    assert verify(old, both) and verify(new, both)          # overlap window
    only_new = {"k2": ("HS256", K2)}
    assert verify(new, only_new)
    with pytest.raises(jv.InvalidToken, match="unknown kid"):
        verify(old, only_new)                               # retired


def test_pyjwt_library_equivalent_rules():
    import jwt                                              # PyJWT 2.10.1
    key = K1
    good = jwt.encode(claims(), key, algorithm="HS256")
    out = jwt.decode(good, key, algorithms=["HS256"], audience=AUD, issuer=ISS,
                     options={"require": ["exp", "iss", "aud", "sub"]})
    assert out["sub"] == "u1"
    unsigned = jwt.encode(claims(), None, algorithm="none")
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(unsigned, key, algorithms=["HS256"], audience=AUD, issuer=ISS)
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(good, key, algorithms=["HS256"], audience="other-api", issuer=ISS)


@pytest.mark.parametrize("kid", [["k1"], {"a": 1}, 5, None])
def test_non_string_kid_is_invalid_token_not_typeerror(kid):
    head = jv.b64e(json.dumps({"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
    body = jv.b64e(json.dumps(claims()).encode())
    with pytest.raises(jv.InvalidToken):                    # pre-signature, attacker controlled
        verify(f"{head}.{body}.AAAA")


@pytest.mark.parametrize("bad", ["9999999999", None, float("nan"), [1], True])
def test_signed_exp_must_be_a_finite_number(bad):
    with pytest.raises(jv.InvalidToken):
        verify(jv.sign_hs256(claims(exp=bad), K1, "k1"))


def test_signed_nbf_must_be_a_finite_number():
    with pytest.raises(jv.InvalidToken):
        verify(jv.sign_hs256(claims(nbf="0"), K1, "k1"))


def test_typ_is_checked_when_expected():
    t = jv.sign_hs256(claims(), K1, "k1")                   # typ "JWT"
    assert jv.verify(t, KEYS, issuer=ISS, audience=AUD, typ="JWT")
    with pytest.raises(jv.InvalidToken, match="wrong token type"):
        jv.verify(t, KEYS, issuer=ISS, audience=AUD, typ="at+jwt")


def test_token_string_is_not_malleable():
    t = tok()
    for variant in (t + "=", t + "==", t + "\n"):
        with pytest.raises(jv.InvalidToken):
            verify(variant)
```

Never key a revocation list on the raw token string (a JWT has to be compared canonically, and even then the string is a bearer secret); use `jti` or a per-user not-before cutoff time.

PyJWT notes (2.10.1): always pass `algorithms=[...]` to `jwt.decode`; pass `audience=` and `issuer=`; add `options={"require": [...]}` because by default `exp`/`aud` are only validated if present.

## 4. OAuth 2.0 / OIDC client rules

Primary sources: RFC 9700 (OAuth 2.0 Security Best Current Practice, BCP 240, January 2025; updates RFC 6749), RFC 7636, ASVS 5.0 V10.

- Authorization Code flow with **PKCE** for every client. RFC 9700 sec 2.1.1: public clients MUST use PKCE; for confidential clients PKCE is RECOMMENDED (and OIDC `nonce` is an allowed alternative with extra precautions); applies to web apps too. Use method `S256` only (`plain` exposes the verifier; ASVS 10.4.6 forbids it). Verifier is 43-128 chars of unreserved characters (RFC 7636 sec 4.1).
- Verifier, `state` and `nonce` are per-transaction random values, bound to the user agent session that started the flow (RFC 9700 sec 2.1.1; ASVS 10.1.2, 10.2.1). Store in the server session (or a signed, short-lived cookie), compare on callback, delete after use.
- Authorization server: exact string match of pre-registered redirect URIs (ASVS 10.4.1; RFC 9700 sec 4.1); no Implicit and no Resource Owner Password grants (ASVS 10.4.4; RFC 9700 sec 2.1.2, 2.4); codes single-use and short-lived (ASVS 10.4.2, 10.4.3); reject a `code_verifier` when no `code_challenge` was sent (PKCE downgrade, RFC 9700 sec 4.8).
- Mix-up defence: when more than one authorization server is used, check the `iss` authorization-response parameter (RFC 9207) or use distinct redirect URIs per server (RFC 9700 sec 4.4; ASVS 10.2.2).
- OIDC ID token (use the library's validator): signature from the pre-configured issuer's JWKS, `iss` equals the configured issuer (OIDC Core 3.1.3.7; ASVS 10.5.3 covers the same check on authorization server metadata), `aud` equals your `client_id` (10.5.4), `exp`, and `nonce` equal to the one sent (10.5.1). Identify the user by `iss` + `sub`, never email (10.5.2, 10.3.3).
- Resource server: accept only tokens whose `aud` is this service (ASVS 10.3.1), decide from `sub`/`scope`, request least scopes (10.2.3, 10.4.11).
- Refresh tokens for public clients: rotate with reuse detection or sender-constrain (DPoP, RFC 9449); give them an absolute expiry (ASVS 10.4.5, 10.4.8). Native apps: external user agent, RFC 8252.
- Prefer an existing library or the framework's OIDC integration (Authlib, django-allauth/`mozilla-django-oidc`, `openid-client`, Auth.js/NextAuth) over a custom flow; configure it to the rules above and test the config.

```python
# file: pkce.py
import base64
import hashlib
import hmac
import re
import secrets


def new_verifier() -> str:
    v = secrets.token_urlsafe(64)             # 86 chars, within RFC 7636's 43..128
    assert 43 <= len(v) <= 128 and re.fullmatch(r"[A-Za-z0-9_\-]+", v)
    return v


def challenge_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def new_transaction() -> dict:
    """Store this in the SERVER-side session before redirecting to the IdP."""
    v = new_verifier()
    return {"verifier": v, "challenge": challenge_s256(v),
            "state": secrets.token_urlsafe(32), "nonce": secrets.token_urlsafe(32)}


def check_callback(txn: dict | None, params: dict, expected_issuer: str | None = None) -> str:
    """Return the authorization code or raise ValueError. Call txn deletion after."""
    if not txn:
        raise ValueError("no transaction in this session")
    if "error" in params:
        raise ValueError("authorization error")
    if not hmac.compare_digest(str(params.get("state", "")), txn["state"]):
        raise ValueError("state mismatch")
    if expected_issuer is not None and params.get("iss") != expected_issuer:
        raise ValueError("issuer mismatch")     # RFC 9207 mix-up defence
    code = params.get("code")
    if not code:
        raise ValueError("missing code")
    return code
```

```python
# file: test_pkce.py
import pytest
import pkce


def test_rfc7636_appendix_b_vector():
    v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce.challenge_s256(v) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_transactions_are_unique_and_callback_checks():
    a, b = pkce.new_transaction(), pkce.new_transaction()
    assert a["state"] != b["state"] and a["verifier"] != b["verifier"]
    assert pkce.check_callback(a, {"state": a["state"], "code": "c1"}) == "c1"
    with pytest.raises(ValueError, match="state"):
        pkce.check_callback(a, {"state": b["state"], "code": "c1"})
    with pytest.raises(ValueError, match="issuer"):
        pkce.check_callback(a, {"state": a["state"], "code": "c", "iss": "https://evil"},
                            expected_issuer="https://idp.example")
    with pytest.raises(ValueError):
        pkce.check_callback(None, {"state": "x", "code": "c"})
```

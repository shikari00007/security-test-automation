# Loading configuration safely

Verified by execution: see [VERIFICATION-NOTES.md](VERIFICATION-NOTES.md) (pydantic-settings 2.16.3 on pydantic 2.14.4; Node `node:test`).

## .gitignore and .env.example (do this before the first commit)

```gitignore
# secrets and local config
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*.tfvars
!example.tfvars
credentials.json
*.tfstate
*.tfstate.*
id_rsa
id_ed25519
.npmrc
.netrc
service-account*.json
.secrets.baseline.local
```

`.env.example` is committed with placeholders only, never working values:

```dotenv
APP_DATABASE_URL=postgres://user:CHANGE_ME@localhost:5432/app
APP_STRIPE_SECRET_KEY=CHANGE_ME
```

`.npmrc` may need to be committed without tokens in some repos; then remove it from the ignore list and use `${NPM_TOKEN}` interpolation instead. Terraform state routinely holds plaintext credentials. `.env.sample` is ignored by `.env.*`; use the `.env.example` name.

Already committed `.env`? `.gitignore` does not untrack it: `git rm --cached .env`, then treat the values as leaked (incident-response.md).

## Python: typed settings, no default for secrets, fail fast

```python
from pydantic import SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="APP_", extra="ignore")

    database_url: SecretStr          # no default: missing => startup failure
    stripe_secret_key: SecretStr
    debug: bool = False              # non-secret settings may have safe defaults


def load() -> Settings:
    try:
        return Settings()
    except ValidationError as e:
        prefix = Settings.model_config["env_prefix"]
        missing = [f"{prefix}{'.'.join(map(str, err['loc'])).upper()}" for err in e.errors()]
        raise SystemExit(f"config error, missing/invalid: {missing}") from None
```

Points (pydantic-settings docs): environment variables take priority over values from the dotenv file; `env_prefix` applies to dotenv and secrets sources too; a field with no default must be supplied by some source, otherwise `ValidationError` ("Field required"). `secrets_dir` (for example Docker/Kubernetes mounted files, `SettingsConfigDict(secrets_dir="/run/secrets")`) is also supported; a missing directory only warns, so keep required fields without defaults so absence still fails. Use `.get_secret_value()` only at the point of use (the connection call), never when logging.

Test (passes):

```python
import pytest
from settings_demo import Settings, load

def test_fails_fast(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # so no stray .env is picked up
    for k in ("APP_DATABASE_URL", "APP_STRIPE_SECRET_KEY"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(SystemExit) as ei:
        load()
    assert "APP_DATABASE_URL" in str(ei.value)

def test_secretstr_masks(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("APP_DATABASE_URL", "postgres://u:fakepw@localhost/db")
    monkeypatch.setenv("APP_STRIPE_SECRET_KEY", "FAKE-not-a-real-key")
    s = Settings()
    assert "fakepw" not in repr(s) and "fakepw" not in str(s)
```

Anti-patterns to flag in review: `os.environ.get("API_KEY", "sk-live-...")`, `SECRET_KEY = "dev-secret"` that is also used in production, `DEBUG=True` default that prints settings, `.env` loaded with `override=True` in production, `print(settings)`.

## Node/TypeScript: dependency-free loader

```js
// config.mjs
const REQUIRED = ["DATABASE_URL", "STRIPE_SECRET_KEY"];

class Secret {
  #v;
  constructor(v) { this.#v = v; }
  reveal() { return this.#v; }
  toString() { return "[SECRET]"; }
  toJSON() { return "[SECRET]"; }
  [Symbol.for("nodejs.util.inspect.custom")]() { return "[SECRET]"; }
}

export function loadConfig(env = process.env) {
  const missing = REQUIRED.filter((k) => !env[k]);
  if (missing.length) throw new Error(`Missing required config: ${missing.join(", ")}`);
  return Object.freeze({
    port: Number(env.PORT ?? 3000),
    databaseUrl: new Secret(env.DATABASE_URL),
    stripeSecretKey: new Secret(env.STRIPE_SECRET_KEY),
  });
}
```

Test (`node --test`, passes): missing -> error names `DATABASE_URL, STRIPE_SECRET_KEY` without values; `JSON.stringify(config)`, template-string and `util.inspect` all show `[SECRET]`. For `.env` loading in development use Node's `--env-file=.env` flag or the `dotenv` package in dev only (not verified here); production reads real environment injected by the platform. A schema library (zod, envalid) is fine if you keep the same rules.

## Client-side bundles: public vs secret keys

| Framework | Exposed to the browser | Rule |
|---|---|---|
| Next.js | variables prefixed `NEXT_PUBLIC_` | Never prefix a secret; server-only code reads unprefixed vars |
| Vite | variables prefixed `VITE_` (import.meta.env) | Same |
| Create React App | `REACT_APP_` | Same |
| Any SPA/mobile | everything in the bundle/binary | Treat as public, readable by anyone |

(Prefix conventions are framework behaviour; confirm in the framework docs for your version.) Checklist:
- Secret keys (`sk_...`, service-role, admin, signing, DB) only on the server; the browser calls your API, which calls the third party.
- Publishable/anon keys are okay only with provider-side restrictions (allowed origins, row-level security, scopes) turned on.
- After building, scan the output: `gitleaks dir --redact --no-banner dist/` and grep for known secret names/prefixes; also check source maps are not publishing server-only code.
- Do not "hide" a secret by base64/obfuscation; that is not protection.
- Mobile binaries and Electron apps are extractable: use per-user short-lived tokens from your backend.

## Containers

Never `ENV SECRET=...`, `ARG SECRET`, or `COPY .env` into an image (layers keep it, cheat sheet: never bake secrets in with ENV/ARG). Inject at runtime from the orchestrator or mount a file; for build-time needs use BuildKit secret mounts (`RUN --mount=type=secret,id=...`; verify against current Docker docs). Add `.env` to `.dockerignore`.

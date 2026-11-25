# SEC-SC-006 field accuracy, iteration 3

Trigger: on an unseen benign set blind triage found 68% of SEC-SC-006 findings were false positives
(translation text, env references, algorithm names, doc file paths, feature flags, documented samples).
Only the generic (non provider-format) detector was narrowed; provider-format tokens and PEM keys keep their
previous behaviour except for the hand-typed placeholder rule below.

## Training corpus (built for this iteration; none of the excluded repos used)
Shallow clones of gofiber/recipes, discourse, spring-petclinic, awesome-compose, wagtail, BookStack,
meilisearch, mastodon, gitea, strapi, cookiecutter-django, jhipster-sample-app, koel, lemmy,
prometheus-community/helm-charts, nextcloud/server (16 repos: Go, Rust, Ruby, Node, Python, Java, PHP, compose/CI).
Run: `audit --type auto --profile standard --no-verify`. Earlier labelled holdout/holdout2 SC-006 rows
(translation YAML/JSON, `catalog:` deps, charset constants, claim names) were used as additional evidence.

## Measured effect (self-labelled, 79 findings before)
| label | before | after |
|---|---|---|
| FP | 68 | 0 |
| TP-opt (dev/test default creds, documented placeholders) | 11 | 6 |
| TP | 0 | 0 |

FP breakdown before: 61 gitea OAuth scope constants (`"read:admin"`), 3 mastodon CJK translations, and one each:
BookStack API-doc sample (`hunter2000` next to example.com), helm field selector, rabbitmq `password_hash`,
nextcloud `'amazons3_accesskey'` constant. Excluding the gitea scope block the rate was 7 FP of 18 (39%) -> 0 of 6.
The 5 TP-opt that disappeared: jhipster base64 "...should-be-changed-in-production" (x2) and 3 strapi redaction-test
tokens typed as `ghp_0123456789abcdef...`. Remaining 6: gitea `SecretKey` default, lemmy default admin password,
nextcloud CI MinIO creds (base64 of a non-placeholder phrase). Prior-iteration holdout FP families (Directus/Zulip
translations, `catalog:` deps, `SECRET_KEY_CHARSET`) are covered by the same rules.

## Behaviour changes (all in supply_chain.py; cases in fixtures/accuracy/web-api-sc-iter3-sc006/cases.json, >=3 neg, >=2 pos each)
1. Non-Latin-script letters in the value (CJK, Cyrillic, Arabic...) => human language, not a key.
2. Locale file names (`de-DE.yaml`, `zh-CN.yml`, `sv.yml`) join the locale-path gate (value must be token-shaped), and the
   unquoted-config branch (yaml/.env/ini) now honours the gate too (previously only the quoted branch did). Region must be
   upper-case/3 digits so `ci-prod.yml` / `app.properties` are not treated as locales.
3. Dependency specifiers (`catalog:`, `workspace:*`, `file:`, `link:`, semver ranges) for packages named `secretlint` etc.
4. Ascending runs of >=8 letters/digits (`abcdefgh`, `01234567`) in generic values => charset/placeholder. For provider tokens
   the run must be >=10 (or a char repeated 10x): `ghp_0123456789abcdef...`, `sk_live_abcdefghij...` are hand-typed placeholders.
5. Algorithm / cipher names made only of known tokens (`HS256`, `aes-256-gcm`, `pbkdf2-sha256`).
6. Relative file paths / secret-file names (`config/secrets/app.yml`, `db_password.txt`); slash-bearing random mixed-case tokens
   (AWS secret keys) are not paths (segments must be lowercase and not digit-letter-digit).
7. Secret-store references (`vault:`, `op://`, `arn:aws`, `ENC[`, `file:`, `sops:`).
8. Lowercase scope identifiers (`read:admin`, `user:email`) and kebab/snake identifiers whose tokens are words with <=2 trailing digits
   (`passwordless-login-v2`, `amazons3_accesskey`).
9. Selector expressions containing `!=`.
10. Base64 whose decoded text is a lowercase replace-me phrase (should/change/replace/your/placeholder/default/do-not/please).
11. Key-name suffixes hash/digest/checksum/fingerprint/thumbprint/selector/algorithm/alg/algo (value names or derives from, not is, a secret).
12. The reserved-domain synthetic-account rule (example.com/.org/.test within +-4 lines, value not high-entropy) now also applies to
    .json/.yml/.http/.txt/.sh files, not just smoke/packaging scripts; `hunter2<digits>` joins the tutorial-sample list.
    (Existing positives `hunter2hunter2` deliberately remain flagged.)
Rejected: widening the env-reference line skip (os.Getenv / ENV.fetch with literal default) - no measured FP and it would hide hardcoded defaults.

## Recall risks
- Passwords that happen to be lowercase kebab/snake words with <=2-digit suffixes (`correct-horse-battery-9`) or `word:word` are now ignored.
- Passwords containing an ascending 8-run (`abcdefgh`) are ignored in generic detection; provider tokens need a 10-run.
- A password in a JSON/YAML/.sh file within 4 lines of an example.com address is ignored unless >=24 chars with entropy >=3.5.
- A real key stored in a file named like a locale (`en.json`, `de-DE.yml`) is only flagged when token-shaped (>=20 chars, letters+digits, entropy>=3.5).
- Real secrets that are values ending in a file extension (`.key`, `.pem`) or starting `vault:`/`file:` are ignored.
- Base64 of a human phrase containing "default/please/your..." is ignored; other base64 (incl. `example-secret-value1`) still flagged.
Seeded recall corpus (AWS, GitHub, Slack, Stripe, Google, SendGrid, npm, Anthropic keys, PEM, DB URLs, .env, CI, compose,
properties, ini; 19 lines): all still flagged (3 positive cases in the field cases file).

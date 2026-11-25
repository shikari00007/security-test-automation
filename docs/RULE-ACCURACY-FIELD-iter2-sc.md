# Field accuracy, iteration 2: supply chain (SEC-SC-006, SEC-SC-001)

Training data: labelled hold-out #1 (69 blind-triaged findings; 25 SEC-SC-006, 4 SEC-SC-001).
Cases: `fixtures/accuracy/web-api-sc-iter2-sc/cases.json` (10 negative, 8 positive).

## SEC-SC-006 behaviour changes

1. **Locale catalogs.** Paths under `language|languages|lang|langs|locale|locales|l10n|i18n|translations|LC_MESSAGES` dirs and `*.po`/`*.pot`:
   generic credential literals and URL credentials are reported only when the value is *token-shaped*
   (ASCII, >=20 chars, no whitespace, letter+digit, entropy >= 3.5). Provider-format tokens (ghp_, AKIA, xox, PEM, ...) are never
   subject to this and are always flagged, so a real-looking token in `locales/en.json` is still a finding.
   The documented AWS key `AKIA...EXAMPLE` is also treated as example text inside locale catalogs.
   Recall risk: a real secret hand-placed in a locale dir that is shorter than 20 chars or low-entropy and not provider-format is missed.
2. **Identifier values.** Name suffixes `claim|prefix|suffix|scheme|cookie|param|attr|attribute` join the existing "names a secret" list;
   values ending in a separator (`django-insecure-`) and underscore-led lowercase snake identifiers (`_app_claim_name`) are not secrets;
   bare words are now unicode-aware (`Lösenord`, `contraseña`). Recall risk: an all-lowercase-word password ending in `-`/`_`, or a
   secret stored in a variable named `*_prefix` etc., is missed.
3. **Shell/env references.** Values that are a single `$VAR`, `${var}`, `${var:-x}` or `$(cmd)` are not literals. Unbraced lowercase
   `$var` is deliberately not matched (could be a real password beginning with `$`). Recall risk: negligible.
4. **Documented example AWS key** in translation strings (see 1). Real-looking AKIA keys in code/config are still flagged.
5. **Tutorial apps** saying "unsuitable for production" are untouched: TP-opt, still flagged (B020 still reported).

## Hold-out #1 effect (SEC-SC-006, 25 labelled rows)

Before this branch's changes on the current iter1 tree: 15 FP remained flagged plus 4 FP already fixed by iter1.
After: all 19 labelled FPs suppressed (15 newly removed by iter2). Removed TP: 0 (B025 still flagged). Removed TP-opt: 0
(B020 still flagged; B006/B008/B017/B022 docs samples were already suppressed by iter1, not by this change).

## SEC-SC-001

No change. B002 (NodeBB `install/package.json`, labelled FP: yarn.lock in an ancestor) is not reproducible from the cloned repo,
which contains no `yarn.lock` at all (the lockfile is absent from the clone), and `_has_lock` already walks ancestors. No evidence
to support a rule change. B001/B003/B004 are TP-opt and must stay. Nested requirements.txt intentionally not chased.

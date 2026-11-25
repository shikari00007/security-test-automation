# Field accuracy, iteration 3: PHP / Java detectors (SEC-WEB-002 / 005 / 006)

Scope: `security_runner/adapters/web_php_java.py` (statement-level taint tracking for PHP, Java and JSP) plus the helper
hooks it exposes to `web.py`. Cases: `fixtures/accuracy/web-api-sc-iter3-phpjava/cases.json` (73 cases, ids `pj3-*`).

## Method

* Training corpus (benign, none of the hold-out repos), shallow clones: phpmyadmin/phpmyadmin, drupal/drupal,
  symfony/symfony, joomla/joomla-cms, roundcube/roundcubemail (PHP); apache/tomcat, apache/maven, apache/jspwiki,
  apache/roller (Java/JSP). All audited with
  `audit --type auto --profile standard --no-verify --fail-on never --report json` before and after the changes.
  (symfony was only measured through the adapter directly: the full audit did not finish in a reasonable time.)
* Findings were read in context and labelled by hand: TP, TP-opt (real but optional / by-design weakness) or FP.
* Recall evidence: labelled hold-out #1/#2 ground truth for PHP/Java/JSP SEC-WEB-002/005/006 (49 entries: DVWA,
  WebGoat, Vulnerable-Web-Application). Detected 41/49 before and 41/49 after, identical set of misses.
* Every change below has >=3 negative and >=2 positive cases in the cases file; (40 of the 73 cases, all of them negatives or JSP-alignment positives) were confirmed to fail on the old adapter; the rest are guard cases.

## Measured effect on the training corpus (PHP/Java/JSP findings of SEC-WEB-002/005/006 only)

| repo | before | after | removed (all labelled FP unless noted) |
|---|---|---|---|
| tomcat (java/ tree) | 10 | 0 | 9 identifier-position SQL with bound values, 1 TRACE echo (`message/http`) |
| roller | 6 | 0 | 2 JSON responses, 4 constant multi-line SQL |
| roundcubemail | 89 | 77 | 6 widget `->show()`, 1 `rcube::Q()`, 5 operator-configured commands |
| joomla-cms | 11 | 8 | 2 `JsonResponse`, 1 comparison-only ternary |
| phpmyadmin | 40 | 38 | 1 internal CLI `git` helper (FP), 1 hashed password (TP-opt) |
| jspwiki | 21 | 5 | 15 SQL with config-sourced identifiers, 1 `text/plain` response |
| drupal, maven | 0 | 0 | |
| **total** | **177** | **128** | 48 FP + 1 TP-opt |

Labels over the corpus: before 147 FP / 30 TP-opt / 0 TP; after 99 FP / 29 TP-opt / 0 TP. Neither corpus contains a
true exploitable defect (benign projects), so the "TP-opt" rows are code such as phpMyAdmin deliberately executing
user-built SQL, `eval`/`shell_exec` of operator templates in Roundcube, or JSPWiki URL parameters concatenated into
tab URLs.

Outside the audited scope (tomcat `webapps/` sample JSPs/servlets, which the audit skips) the adapter went from 32
findings to 1 (31 FP: `HTMLFilter.filter` / `Escape.*` output, typed `(Session) request.getAttribute()`); symfony
`src/` adapter findings 6 -> 3 (internal CLI helpers; the remaining 3 are TP-opt dev scripts).

The remaining FP (99) are almost all produced by the generic PHP SQL concatenation line heuristic in `web.py`, not by
this adapter (see "Needed change in web.py").

## Behaviour changes

1. **Comparison operands are not taint carriers.** `$_GET['m'] === 'edit' ? 'A' : 'B'`, `x == null ? "" : escape(x)`:
   an occurrence that is directly compared (`==`, `===`, `!=`, `!==`, `<=>`, `instanceof`) yields a boolean. Cases
   `pj3-002-*-cmp-*`. Risk: `echo $_GET['a'] == 'x' ? ...` only suppresses the condition occurrence; any other occurrence
   in the branches is still reported (positive case `cmp-branch`).
2. **Operator-configured / escaped command lines** (PHP SEC-WEB-005 name heuristic `$cmd`, `$args`, ...): a variable
   whose value only comes from configuration (`->config->get()`, `Config::get`, `getenv`, `$_ENV`, `get_option`,
   `getParameter`), from other such variables, or from `escapeshellarg`/`array_map('escapeshellarg', ..)`/numeric
   wrappers is trusted. `addslashes` is deliberately NOT accepted for shell sinks. Cases `pj3-005-neg-php-*`.
3. **Name heuristic skipped in CLI-only files** (shebang, `$argv`, `PHP_SAPI`, `STDIN`, console `Command` classes) that
   never touch a request. A helper `function run($cmd)` in a normal file is still reported (existing case kept).
4. **More HTML/JSON escaping helpers recognised** (PHP): `rcube::Q`, `check_plain`, `filter_xss*`, `Xss::*`, any
   `*json*` (`JsonResponse`, `Json::encode`, `jsonify`) and `*hash*` wrappers; HTML builder widgets (`new html_*`,
   `new Html*Field/Select/...`) whose methods escape (`$field->show($_POST['x'])`). Unknown formatters still flag.
5. **Typed request getters** (`->get('id', 0, 'int')`, `'cmd'`, `'uint'`, ...) are not sources.
6. **Java content type state.** After `setContentType("application/json" | "text/plain" | "message/http" | ...)` in
   the same method the writer is no longer an XSS sink; a later `text/html` re-arms it. JSON mapper calls
   (`writeValueAsString`, `toJson`, ...) count as encoders.
7. **Java sanitiser classes by qualified name**: `HTMLFilter.filter`, `Escape.htmlElementContent`, `HtmlUtils.*`,
   `*Escap*.*`, `Xss*.*`, `ESAPI.*`, `Encoder.*`, `*Helper.escape*`.
8. **`(Session) request.getAttribute("x")`**: an attribute cast to an application object type (not String/Object/
   CharSequence) is a server-side object, not request text. `(String) getAttribute(..)` and uncast values still flag.
9. **Config-sourced identifiers (Java SQL).** Names whose every assignment in the file is `props.getProperty(..)`,
   `getInitParameter(..)`, `System.getenv(..)`, a literal/constant, or an `@Value` field are treated as identifiers
   chosen by the operator (`m_name`, `idField`, `userTable`). Names ending in `Col/Cols/_col/Tbl` are identifier-like,
   too. A field that is also assigned from a parameter in the file is NOT trusted (positive case).
10. **Multi-line concatenation** (`java_line_dynamic`): a continuation line (`"..." +` / `+ "..."`) is judged on the
   whole statement, so statements made only of literals/identifiers stop being reported while a dynamic operand on any
   line keeps the finding (pre-existing positive `web006-pos-java-concat-multiline` still passes).
11. **Bug fix: JSP line numbers.** `_prep_jsp` appended a newline for every scriptlet, so lines drifted (+1 per `<% %>`),
   which made the evidence integrity check fail (`evidence ... does not match the file`) and aborted the audit of
   JSP-heavy projects (jspwiki). Scriptlet comments are now stripped per block so they cannot swallow the next block.
   Cases `pj3-002-pos-jsp-line-alignment`, `pj3-002-pos-jsp-comment-scriptlet`.

## Needed change in web.py (not done here: web.py is owned elsewhere)

The generic PHP SQL concatenation heuristic in `web_006` (`return rel.endswith(".php") and bool(re.search(...))`) is the
source of ~93 of the 119 remaining PHP SQL findings on the corpus (identifier interpolation: `table_name()`,
`quoteName()`, `{$this->table}`, `$groupTable`, `(int)` casts). This adapter now exposes
`php_line_dynamic(line, file_text="")`; wiring it in is one line:

```python
return rel.endswith(".php") and bool(re.search(...)) and _pj.php_line_dynamic(line, ctx.read(rel))
```

Measured offline on the corpus findings: suppresses 93/119 (all labelled FP) and loses 0 of the 18 PHP SEC-WEB-006
ground-truth lines in DVWA / Vulnerable-Web-Application. Operands it accepts: table-name/quote helpers, `*table*`,
`*column(s)*`, `cols`, `vals`, `prefix`, `schema` variables/properties, numeric casts, constants. It is conservative:
anything it cannot classify stays a finding. It is not covered by `cases.json` (cases go through `observations_for`),
so it is untested until web.py calls it.

## Recall risks

* (1) `x == null ? "" : x` style code where the compared value is the only tainted occurrence cannot hide a real
  flow, but a hand-rolled check such as `if ($_GET['a'] == $_GET['b']) echo ...` is no longer a source for that
  comparison (the echo of either value still is).
* (2)/(3) A command assembled from a trusted-looking variable that actually receives request data through a path the
  adapter cannot see (e.g. `$cmd` set by a setter) is not flagged in files with a CLI marker and no request access.
* (4) A class named `html_*` / `Html*Field` that does not escape would hide a reflected XSS; likewise a function whose
  name contains `json`, `hash`, `xss`.
* (5) Joomla-style typed getters with `'string'` remain sources; only numeric/charset-restricted filters are trusted.
* (6) An application that sets `application/json` but reflects into HTML elsewhere in the same method would be missed.
* (8) Controllers that store a request-derived object (not String) in an attribute and print it.
* (9) A field read from `getProperty` that is later overwritten from outside the file (setter generated by Lombok)
  is trusted; user-chosen `*Col`/`*Table` names (e.g. a `sortCol` copied from a request parameter) are no longer
  reported when the value reaches SQL only through such a variable, unless the file assigns it from a parameter.
* Hold-out ground truth shows no loss (41/49 both runs); the 8 misses (xss_d DOM sinks, API source, WebGoat
  multi-statement flows) are pre-existing.

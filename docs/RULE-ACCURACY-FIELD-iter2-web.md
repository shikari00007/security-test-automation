# Field accuracy, iteration 2: SEC-WEB-002 / SEC-WEB-005 / SEC-WEB-006

Scope: false-positive families from independent triage of hold-out #1 plus recall for PHP, Java and a few Node/Svelte/EJS
patterns. Corpus: `fixtures/accuracy/web-api-sc-iter2-web/cases.json` (101 cases, every behaviour change has at least 3 benign
look-alike negatives and 2 positives). Implementation: `security_runner/adapters/web.py` and the new
`security_runner/adapters/web_php_java.py` (statement-level request-taint tracking for PHP, Java and JSP).

Hold-out #1 numbers (rules run on the cloned repos; ground truth = `ground-truth.json`, labels = `baseline-labels.json`):

| Rule | Recall before | Recall after | Labelled FPs removed | Labelled TP/TP-opt removed |
|---|---|---|---|---|
| SEC-WEB-002 | 6/27 | 19/27 | 9/9 | 0 |
| SEC-WEB-005 | 5/14 | 10/14 | 1/1 | 0 (one TP-opt, B055, was already gone after iteration 1) |
| SEC-WEB-006 | 16/17 | 16/17 | 4/4 | 0 |

The hold-out #1 files informed the design, so these are training-set numbers, not a prediction for fresh code.

## Design rule for the new PHP/Java detectors
A finding needs request-derived data reaching the sink: a source on the same statement, or a variable assigned from one
earlier in the same function and not passed through a sanitiser/cast/validator. Java SQL/command strings may also be reported
for an SQL-looking literal concatenated (or `String.format`-ed) with a clearly dynamic operand; operands that are constants,
numeric-typed (`int`, `long`, ...), `Integer.parseInt(..)`, `.size()/.length()`, table/column/limit style names or
`String.join(.., nCopies(.., "?"))` placeholders are ignored. Prepared statements and constants never report. Results of
query/exec calls do not propagate taint (a result set is not request data). Tests, vendored and build directories stay excluded.

## Changes

### SEC-WEB-002
| Change | Language | Recall risk |
|---|---|---|
| Helper calls whose arguments are ALL literals are safe operands when the helper is an icon/translation/i18n/skeleton family (`icon`, `translate`, `__`, `_`, `t`, `$t`, `gettext`, `i18n*`, `*.skeleton.*`), including `await translate(`literal template`)` and literal object arguments. Reader-style names (`getItem`, `get`, `val`) with literal arguments stay reported. | JS/TS/Vue | A custom helper named like these that returns attacker data would be missed. |
| `a.outerHTML = b.outerHTML` / `a.innerHTML = b.innerHTML` (pure DOM-to-DOM copy) not reported; `b.outerHTML + extra` still is. | JS/TS | The copied node may itself contain unsafe markup that was injected elsewhere (reported at that site). |
| NEW: Svelte `{@html expr}` treated like `v-html` (same operand analysis); EJS `<%- expr %>` (unescaped output) reported unless it is an include/partial/layout `body`/`content` placeholder, a literal or a sanitised value. `*.ejs` added to the globs. | Svelte, EJS | EJS layout placeholders with unusual names will be reported (precision cost); `JSON.stringify` inside `<script>` is not specially handled. |
| NEW: PHP `echo/print/printf/die/exit` and `<?= ?>` of request data (`$_GET/$_POST/$_REQUEST/$_COOKIE`, selected `$_SERVER` keys, `$request->input()`...), plus HTML strings (`$html .= '<pre>' . $_GET[..]`) built from it, unless wrapped in `htmlspecialchars/htmlentities/esc_*/strip_tags/intval/json_encode/...` or cast to int. JSON/plain-text responses are skipped. `str_replace`-style blacklists are NOT sanitisers. | PHP | Stored XSS (database values) is not tracked; custom escaping helpers with unusual names are reported; validation through `preg_match/ctype_*/is_numeric/in_array` removes taint, so a validation that does not cover the output context is missed. |
| NEW: Java/JSP writer output (`response.getWriter().println/print/write/append/printf`, `PrintWriter`, `out`, JSP `<%= %>`) of request parameters (`request.getParameter/getHeader/...`, `@RequestParam`-style bound parameters) unless encoded (`Encode.forHtml*`, `escapeHtml*`, `ESAPI encodeFor*`, ...) or parsed to a number. | Java, JSP | Spring `@ResponseBody` string returns and EL `${param.x}` are not covered. |

### SEC-WEB-005
| Change | Language | Recall risk |
|---|---|---|
| Files under `.github/`, `.gitlab/`, `.circleci/` are out of scope (CI helper scripts run in the pipeline, not on request data). | Python, JS | A real vulnerability in a CI-hosted script is not reported. |
| NEW: `<obj>.eval/evaluate/runInNewContext/runInThisContext(...)` is reported when its arguments contain `req/request.body|query|params|headers|cookies`. | JS/TS | Request data reaching the evaluator through an intermediate variable is not tracked there. |
| NEW: PHP `eval/assert/create_function` and `system/exec/shell_exec/passthru/popen/proc_open/pcntl_exec`, and backticks, fed by request data or by a variable named `$cmd/$command/$input/$payload/$expr/$code/$args/$params` that is not provably constant. `escapeshellarg/escapeshellcmd/intval` and validation guards are accepted. | PHP | The name-based path can report a `$cmd` computed from trusted config. |
| NEW: Java `Runtime.exec(String)` and `new ProcessBuilder(..)` with request data or a concatenated non-constant operand; array/varargs forms only with a shell launcher (`sh -c`, `cmd`, `powershell`); `ScriptEngine/GroovyShell .eval/evaluate`, SpEL `parseExpression`, OGNL/MVEL with request data (file must reference the scripting API). | Java | Argument-injection through a plain argument vector (`new String[]{"ls", tainted}`) is intentionally not reported. |

### SEC-WEB-006
| Change | Language | Recall risk |
|---|---|---|
| A line carrying `# noqa: ... S608` (ruff) or `# nosec` (bandit) is treated as an acknowledged statement. | Python (any line-based language) | An author may suppress a real injection. |
| Compiled-SQL wrapper: `SELECT * FROM ({})` / `FROM {placeholder_rows}` / `(%s) subquery` where the only dynamic piece is a variable named `*sql`, `*query`, `subquery`, `compiled*` or `placeholder_rows`. | Python | A variable with such a name that holds user text is missed. |
| Identifier interpolation after `FROM/INTO/UPDATE/TABLE/JOIN/ON/TRIGGER/INDEX` is safe only with explicit helper evidence (`get_*name*(..)`, `quote_*(..)`, `qn(..)`, `escape_identifier`, `quoted_name`); in a statement that also contains DDL/PRAGMA/TRIGGER keywords, `*_table`, `table_name`, `column_name`, `index_name`, `trigger_name`, `schema_name` placeholders are accepted too. Value interpolation (`VALUES ('{who}')`, `WHERE c = '{x}'`) still reports. | Python | An identifier helper that does not really validate is trusted. |
| Java: the generic "SQL literal plus concatenation" line match now ignores lines whose operands are all constants, numeric-typed, parsed numbers or table/column/limit style names. | Java | A numeric-looking name declared with a non-numeric type elsewhere is not tracked per method. |
| NEW: PHP sinks `mysql_query/mysqli_query/pg_query/...`, `->query/->exec/->prepare/DB::select/whereRaw...` fed by request data (direct, or through a variable built across several lines, which the line-based detector missed). Prepared statements with bound parameters are not reported. Findings on a line the legacy detector already reports (or whose variable was built on such a line) are not duplicated. | PHP | `intval/escape_string/addslashes` are accepted as sanitisers (escaping in an unquoted numeric context is still injectable). |
| NEW: Java `Statement.executeQuery/executeUpdate`, `prepareStatement/prepareCall`, `createQuery/createNativeQuery/createSQLQuery` (any dynamic or tainted argument), and `execute/query/update/addBatch/queryFor*` (only when the argument is SQL-looking) with request data or a non-constant concatenation / non-numeric `String.format`; StringBuilder building is followed through `.append`. | Java | Queries assembled in helper classes across method boundaries are not followed. |

Not done (documented for the next iteration): Jinja/Django `|safe` in templates, Python request-fed `subprocess.Popen(var, shell=True)` through a bare variable,
stored/DB-sourced PHP XSS, NoSQL `$where` string building in JS (no sufficiently precise signal found), SQL in JSP.

# Accuracy iteration 3 (Python and TypeScript/JavaScript recall): SEC-WEB-002 / 005 / 006

Goal: raise recall on Python and TypeScript/JavaScript (hold-out baseline: Python 2/20, TypeScript 3/17) without materially
hurting precision. PHP/Java were handled in an earlier iteration (`web_php_java.py`, untouched here).

## What changed

New module `security_runner/adapters/web_python_ts.py`, wired into `web.py` through `py_ts_obs()` exactly like
`php_java_obs()`: its findings are added after the legacy line detectors and any line (or construction line of a variable
that is executed) already reported by the legacy detectors is skipped, so a statement is never reported twice.

Design: precision-first request-taint tracking, no third-party parser.

* **Python** is parsed with `ast`. Per function (flow-insensitive, two sweeps, closures inherit the parent state) a name is
  *tainted* when it is assigned from a request source or from a tainted name; tuple assignments are tracked element-wise;
  f-strings, `%`, `.format`, `+`, str methods, `re.*`, `json.loads`, `unquote*`, `open().read()` pass taint on. Unknown
  function calls do **not** pass taint (ORM lookups, helpers), comprehensions evaluate their element expression (so
  `[escape(x) for x in tainted]` is clean).
* **Sources**: `request.args/form/values/json/cookies/headers/data/files/GET/POST/COOKIES/META/body/query_params/path_params/
  view_args/environ/url/path/...` (Flask, Django, DRF, FastAPI, aiohttp, bottle, pyramid, falcon), `self.get_argument()`,
  `self.request.*` (tornado), `self.path/headers/rfile` in `http.server` handlers, AWS-Lambda `handler(event, context)`;
  parameters of route-decorated handlers (`@app.route/get/post/...(...)`), of Django function views (`request` first) and of
  class-view `get/post/...` methods. Not tainted: `self`, `request`, db/session objects, `id/pk/*_id/page/limit/offset`-style
  names, int/float/bool/UUID/date annotated parameters, `Depends(...)` parameters, one/two-letter and object-like names
  (`obj`, `form`, `instance`, ...) in non-route functions.
* **Neutralisers** (taint removed): `int/float/bool/len/...`, `escape/html.escape/conditional_escape/format_html/bleach.clean/
  nh3.clean/strip_tags/quote/urlencode`, `shlex.quote/join/split`, `secure_filename/slugify`, `re.sub(r"[^...]", "", x)`,
  psycopg2 `sql.Identifier/Literal/Placeholder`, `bindparam`, `escape_string`; names compared against a closed set
  (`x in (..)`/`x not in ALLOWED`), `.isdigit()/.isalnum()` guards, anchored `re.match` guards, `validate*()` calls anywhere in the
  function; lookups in literal / ALL_CAPS tables.
* **TypeScript/JavaScript** is tokenised (strings, template literals with nested `${}`, comments, regex literals, brackets)
  and scopes (functions, arrows, methods) are found by bracket matching. Sources: `req/request/ctx/event.body|query|params|
  headers|cookies|payload|...` (dot and `['x']` access), destructured `{ body, query, params }` of handler parameters, NestJS
  `@Body/@Query/@Param/@Headers` parameters (not when typed `number`), AWS-Lambda `event`, browser sources
  (`location.search/hash/href`, `document.URL/referrer/cookie`, `window.name`, Angular route `snapshot.params/queryParams`).
  Neutralisers: `Number/parseInt/encodeURIComponent/escape*/sanitize*/DOMPurify/xss/...` enclosing the operand, comparison /
  `.length` / `?` test positions, `.replace(/[^...]/g, '')` allow-list stripping, tagged templates (`sql\`...\``).

### Behaviour changes per language and rule

| Lang | Rule | Newly reported (needs a request/route/event source or a clearly dynamic function argument reaching the sink) |
|---|---|---|
| Python | 002 | `render_template_string/from_string/Template(src)` whose source is request-derived (incl. `except ... as e` text when the `try` handled request data); `Markup()/mark_safe()/SafeString()` of request data; HTML strings (HTML literal fragment + request operand) that are returned from a Flask-style route, written with `wfile.write/self.write`, or passed to `HttpResponse/make_response/HTMLResponse`, unless escaped, JSON or a non-HTML content type; Jinja `Environment/setup_jinja/aiohttp_jinja2.setup(autoescape=False)` and `jinja_env.autoescape = False` in files that import a web framework; Jinja/Django templates `{{ x|safe }}` when a view passes request data under that key to that template (or the variable has an obviously user-input name such as `query/search/username`) |
| Python | 005 | `os.system/popen`, `commands.*`, `asyncio.create_subprocess_shell`, `subprocess.*` with `shell=True` **or** a string command, `sh -c`/`bash -c` argv, `os.exec*/spawn*`, `eval/exec/compile`, `<mod>.eval()` evaluators, `pickle/marshal/dill/jsonpickle` loads and `yaml.load` with an unsafe/absent loader, all fed by request data |
| Python | 006 | `cursor/connection/engine.execute*`, `executescript`, `sqlalchemy.text()`, `Model.objects.raw`, `.extra(where=...)`, `RawSQL`, `read_sql*` with an SQL literal combined (f-string, `%`, `.format`, `+`, also through a local variable) with request data; and, weaker, with a plain function argument that sits in a *value position* (inside quotes, after `=`/`<`/`>`/`LIKE`/`IN (`/`VALUES (`) and is not identifier-like (`table`, `column`, `order`, `sort`, `schema`, ...) |
| TS/JS | 002 | Angular `bypassSecurityTrustHtml/Script` on any non-literal value (also `...Url/ResourceUrl/Style` when the value is route/request derived); Angular `[innerHTML]` in a `*.component.html` whose component marks data with `bypassSecurityTrustHtml`; `res.send/write/end`, `reply.send`, `ctx.body =` with an HTML string interpolating request data; `ejs/pug/nunjucks/handlebars/_.template` compile/render of request-derived source; jQuery `.html/.append/.prepend/...` of browser-controlled data |
| TS/JS | 005 | `child_process.exec/execSync` (bare `exec` only in files that use child_process/shelljs/execa), `spawn/execFile` with `shell:true` or `sh -c`, `eval`, `new Function`, `vm.runIn*/vm.Script`, `math.eval`-style evaluators and `unserialize`, fed by request/event/NestJS-parameter data through same-function dataflow |
| TS/JS | 006 | `query/execute/raw/whereRaw/orderByRaw/...` statements (incl. multi-line template literals and statements executed through a variable) and Mongo `$where` expressions built from request data; function arguments only for a db/pool/client receiver (never `this.*`), an SQL literal and a value position, and never through `sanitize*/escape*/encode*` helpers |

`web.json`: only `file_globs` (SEC-WEB-002 now lists `*.py` and Jinja template extensions) and `expected_secure_behavior`
text changed; confidence, profiles and severity are untouched.

## Measured effect

Ground truth recall (hold-out #1 and #2 labelled locations; hit = finding of the rule in the same file within +-2 lines).
These repositories were *studied while building the detectors*, so this is a training-set number, not an unbiased one.

| Group | Before | After |
|---|---|---|
| Python entries (SEC-WEB-002/005/006) | 3 / 19 | 18 / 19 |
| TypeScript/JavaScript entries | 14 / 27 | 24 / 27 |
| Template files (`.html`: Jinja `|safe`, Angular `[innerHTML]`, Thymeleaf, ...) | 4 / 12 | 6 / 12 |
| Python + TS/JS + templates | 21 / 58 | 48 / 58 |

Still missed: DVWA `high_unobfuscated.js` (constant-string `eval`, weak pattern hit), juice-shop `b2bOrder.ts` (`vm.runInContext`
with a literal script over a sandbox object), DSVW stored XSS (rows read from the database, no DB taint), juice-shop
`[innerHTML]` bindings whose component does not bypass the sanitiser (Angular sanitises them; deliberately not reported),
WebGoat Thymeleaf `th:utext` and `$().html(ajaxResult)` (server-supplied data, not browser-controlled), pygoat `innerHTML`
templates inside `.html`.

Semi-independent labelled corpora (not used for design, only for checks; `ruleid:`/`ok:` annotations of semgrep-rules python +
javascript + typescript folders mapped to our three rules, many of those rules are audit/best-practice rules that are out of
scope here).

| Corpus | Before | After |
|---|---|---|
| semgrep-rules `ruleid` hits, SEC-WEB-002 | 10 / 242 | 53 / 242 |
| semgrep-rules `ruleid` hits, SEC-WEB-005 | 72 / 249 | 98 / 249 |
| semgrep-rules `ruleid` hits, SEC-WEB-006 | 114 / 162 | 126 / 162 |
| semgrep-rules `ok:` lines wrongly flagged (all rules) | 6 | 6 (no new false positive) |
| njsscan `true_positives` JS samples | not measured | 32 new findings, all genuine (XSS, eval, exec, SQL); `true_negatives`: 0 findings |

Precision check on benign code (new findings only; the legacy detectors are unchanged): django, djangoproject.com,
django-realworld-example-app, flask, full-stack-fastapi-template, frappe, superset, netbox, wagtail, redash, zulip, express,
nest, NodeBB, node-express-realworld, directus, Ghost, spring-petclinic, fastapi, starlette, microblog, saleor, strapi,
typeorm, angular-realworld-example-app, cal.com (26 repositories, several million lines): **1 new finding in total**
(cal.com `intercom/api/get.ts`: `req.query.url` interpolated into a script block returned as `text/html`; labelled TP).
The first iteration of the analyser produced 33 findings on the same corpus; all of those were false positives and led to
the following hard exemptions: ORM/lookup calls and unknown calls do not carry taint, `exc` taint does not feed `mark_safe`,
comprehension targets only taint their element expression, double-quoted identifiers and `(`/`,` positions are not value
positions, function-argument taint is dropped for JS/TS when it flows through another call or a sanitiser-named helper,
one/two-letter and object-like parameter names are not tainted outside routes, `jinja2` alone does not make a file "web".
On the deliberately vulnerable training apps (DSVW, dvpwa, Vulnerable-Flask-App, pygoat, dvna, dvws-node, NodeGoat, juice-shop,
vulnerable-node) the labels of every new finding that was read were TP (SQL concatenation, shell strings, SSTI, eval, pickle,
bypassSecurityTrust, `$where`).

## Test cases

`fixtures/accuracy/web-api-sc-iter3-pyts/cases.json` (109 cases, each file synthesised, no third-party code): per detection
group at least 2 positive and 3 negative cases (groups: Python SSTI, Markup/mark_safe, HTML return/HttpResponse, autoescape,
`|safe` templates, shell sinks, eval/pickle/yaml, request SQL, argument SQL; JS Angular bypass, `[innerHTML]`, `res.send`
HTML, template-engine SSTI, jQuery, exec/spawn, eval/Function/mathjs, SQL, `$where`, Lambda/Nest/FastAPI sources).
Negatives are constants, parameterised queries, escaped output, `shlex.quote`, argv lists without a shell, validated ints /
closed sets, `Depends`/int-typed parameters, ORM calls, tagged templates, `noqa: S608`.
The legacy detectors still report some benign look-alikes of their own (e.g. `os.system('tail -n %d' % n)`,
`${parseInt(x)}` in a template literal): those are pre-existing, outside this module, and no fixture asserts them silent.

## Recall risks and known limits

* Flow-insensitive validation: a closed-set / `isdigit` / `validate*()` guard anywhere in a function removes taint for the
  whole function, so an unguarded earlier use is missed.
* No inter-procedural taint: request data passed to a helper (`run(cmd)`) and used there is only found when the helper is
  itself a route/view/Lambda handler or the legacy detector flags it; unknown calls (including wrappers around escaping) block taint.
* Database-originated data (stored XSS, second-order SQLi) is not a source; `except ... as e` text is the only non-request
  source and is only used for template source / HTML-string sinks.
* Python 2 files and files with syntax errors are skipped (no `ast`); module-level scripts are analysed only for
  assignments and sinks inside functions.
* Angular `[innerHTML]` is only reported when the sibling component calls `bypassSecurityTrustHtml`; templates in
  separate libraries or inline templates are not linked. `bypassSecurityTrustHtml` of server data (captcha SVG, challenge
  descriptions) is reported even when the server content is trusted (a reviewer decision, labelled TP-opt).
* Jinja `|safe` needs either a view that visibly passes request data under that key, or a user-input-looking name; names such as
  `markdown`/`rendered` coming from sanitising code are not reported.
* JS/TS weak (function-argument) SQL only for db/pool/client receivers; `this.query(...)` helpers, query builders and
  ORMs (TypeORM, Prisma tagged templates) are not covered.
* Minified/very large (>600 kB) JS/TS files are skipped by the tokenizer.
* Reports are one finding per line; a sink statement spanning several lines is reported at the call line.

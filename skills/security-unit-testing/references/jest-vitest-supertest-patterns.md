# Jest / Vitest / Supertest patterns

Full, executed project: `templates/express-jest/` (41 tests; 20 red on vulnerable, 41 green on fixed).

## Principles

- Export `createApp(options)` separately from `listen()`; Supertest drives the app in-process (`request(app)`), no port, no network.
- Build a fresh app per test (`build()` helper) so state is isolated; `jest --runInBand` is not required for correctness, only for easier debugging.
- Inject the logger (`createApp({ logger })`) so the test can pass `jest.fn()` spies and scan calls for a canary secret.
- Mark the fix toggle only in templates; in a real repo there is one app.

## Table-driven

```js
test.each([['alice', 1, true], ['alice', 2, false], ['carol', 1, false]])(
  'read note: %s -> note %i allowed=%s', async (actor, id, allowed) => {
    const app = build();
    const res = await request(app).get(`/notes/${id}`).set(await login(app, actor));
    if (allowed) expect(res.status).toBe(200); else expect([403, 404]).toContain(res.status);
  });
```

Jest 30 `test.each` with arrays of arrays works as above; `%i`/`%s` fill the title. Vitest: same shape with `import { describe, it, expect } from 'vitest'` and `it.each` / `describe.each` (a three-row Supertest table was executed with vitest 5.1.2). Differences to remember: Vitest needs the imports (or `globals: true`), spies are `vi.fn()` and fake timers `vi.useFakeTimers()`; Jest uses `jest.fn()` / `jest.useFakeTimers()`.

## Token negative tests (jsonwebtoken 9)

- Wrong key: `jwt.sign(claims, 'other-key')`.
- Expired: `jwt.sign({ ...claims, exp: Math.floor(Date.now()/1000) - 10 }, KEY, { noTimestamp: true })`.
- `alg: none`: hand-build `base64url(header).base64url(payload).` with an empty signature (building it by hand keeps the test independent of library signing options).
- Tampered payload: keep header and signature, replace payload.
- The verifier under test must pass `{ algorithms: ['HS256'] }` (ASVS 9.1.2: allowlist, no `none`); assert behaviour, not the option.

## Express specifics

- Headers: `expect(res.headers['x-content-type-options']).toBe('nosniff')`; also `x-powered-by` undefined (`app.disable('x-powered-by')`, or helmet if the project uses it; test the outcome either way).
- Malformed JSON: send `.set('Content-Type','application/json').send('{"body": ')` and assert `400` plus no `stack`/`node_modules`/` at ` in the body. Express's default error handler prints stacks outside production (`NODE_ENV`); test with the same env as production or install your own handler, and assert on the real handler.
- Body size: `express.json({ limit })` returns `413`; add an oversized-body case.
- Route completeness: Express 5 `app.router.stack`; Express 4 `app._router.stack` (the template tries both).
- Async handlers: Express 5 forwards rejected promises to the error handler; Express 4 does not, so test that a thrown async error yields the generic `500`.

## Gotchas

- `expect(...).not.toContain(secret)` is vacuous if nothing was logged: pair it with `expect(logged).toContain('alice')`.
- Avoid `setTimeout`-based waits; use fake timers or injected clocks.
- Do not leave `.only` in security tests; add `eslint-plugin-jest/no-focused-tests` and `no-disabled-tests` in CI.

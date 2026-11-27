'use strict';
const { build, login, request } = require('./helpers');

describe('output encoding, validation, headers, leakage, logs', () => {
  test('stored markup is HTML-escaped when rendered', async () => {
    const app = build();
    const h = await login(app, 'alice');
    const marker = '<b id="sut-marker">x</b>'; // harmless markup marker, not a script
    const { body } = await request(app).post('/notes').set(h).send({ body: marker });
    const res = await request(app).get(`/notes/${body.id}/html`).set(h);
    expect(res.text).not.toContain('<b id="sut-marker">');
    expect(res.text).toContain('&lt;b');
  });

  test.each([['a', 201], ['a'.repeat(1000), 201], ['', 422], ['a'.repeat(1001), 422], [null, 422], [123, 422], [['a'], 422]])(
    'note body boundary %#', async (body, expected) => {
      const app = build();
      expect((await request(app).post('/notes').set(await login(app, 'alice')).send({ body })).status).toBe(expected);
    });

  test('malformed JSON does not leak stack traces', async () => {
    const app = build();
    const res = await request(app).post('/notes').set(await login(app, 'alice'))
      .set('Content-Type', 'application/json').send('{"body": ');
    expect(res.status).toBe(400);
    expect(res.text).not.toMatch(/stack|node_modules|SyntaxError| at /);
  });

  test('security headers are present', async () => {
    const app = build();
    const res = await request(app).get('/notes').set(await login(app, 'alice'));
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['cache-control']).toContain('no-store');
    expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('a failed login does not log the password', async () => {
    const logger = { warn: jest.fn(), info: jest.fn(), error: jest.fn(), log: jest.fn() };
    const secret = 'pw-synthetic-canary-7731';
    await request(build({ logger })).post('/login').send({ username: 'alice', password: secret });
    const logged = JSON.stringify(Object.values(logger).flatMap((f) => f.mock.calls));
    expect(logged).not.toContain(secret);
    expect(logged).toContain('alice'); // control: logging happened, so the absence above means something
  });
});

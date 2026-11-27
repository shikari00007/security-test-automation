'use strict';
const { build, login, forge, request, jwt } = require('./helpers');

const status = async (app, headers) => (await request(app).get('/notes').set(headers)).status;

describe('authentication negative paths', () => {
  test('control: a valid token works', async () => {
    const app = build();
    expect(await status(app, await login(app, 'alice'))).toBe(200);
  });

  test.each([[{}], [{ Authorization: 'Bearer' }], [{ Authorization: 'Basic abc' }], [{ Authorization: 'Bearer not.a.jwt' }]])(
    'missing/malformed header %j is 401', async (h) => { expect(await status(build(), h)).toBe(401); });

  test('token signed with the wrong key is rejected', async () => {
    expect(await status(build(), forge({}, { key: 'some-other-signing-key-0123456789-xyz' }))).toBe(401);
  });

  test('expired token is rejected', async () => {
    const exp = Math.floor(Date.now() / 1000) - 10;
    expect(await status(build(), forge({ exp }))).toBe(401);
  });

  test('alg none token is rejected', async () => {
    const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const token = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'adam', role: 'admin', tenant: 'tenant-a', jti: 'n1' })}.`;
    expect(await status(build(), { Authorization: `Bearer ${token}` })).toBe(401);
  });

  test('tampered payload with original signature is rejected', async () => {
    const app = build();
    const [h, , s] = (await login(app, 'alice')).Authorization.slice(7).split('.');
    const p = Buffer.from(JSON.stringify({ sub: 'adam', role: 'admin', tenant: 'tenant-a', jti: 'x' })).toString('base64url');
    expect(await status(app, { Authorization: `Bearer ${h}.${p}.${s}` })).toBe(401);
  });

  test('logout invalidates the token', async () => {
    const app = build();
    const h = await login(app, 'alice');
    expect((await request(app).post('/logout').set(h)).status).toBe(204);
    expect(await status(app, h)).toBe(401);
  });

  test('lockout after repeated failures, even with the right password', async () => {
    const app = build();
    for (let i = 0; i < 5; i++) {
      expect((await request(app).post('/login').send({ username: 'bob', password: 'wrong' })).status).toBe(401);
    }
    expect((await request(app).post('/login').send({ username: 'bob', password: 'pw-bob-test' })).status).toBe(429);
  });
});

'use strict';
const { build, login, request } = require('./helpers');
const pm = require('./permissionMap');

const DENIED = [403, 404];
const concrete = (p) => p.replace(':id', '1');
const send = (app, key, headers = {}) => {
  const [method, path] = key.split(' ');
  let r = request(app)[method.toLowerCase()](concrete(path)).set(headers);
  if (key === 'POST /notes') r = r.send({ body: 'synthetic' });
  return r;
};

describe('authorization matrix (generated from permissionMap.js)', () => {
  test('every registered route has a policy entry', () => {
    const app = build();
    const routes = [];
    (app.router?.stack || app._router.stack).forEach((l) => {
      if (l.route) Object.keys(l.route.methods).forEach((m) => routes.push(`${m.toUpperCase()} ${l.route.path}`));
    });
    expect(routes.sort()).toEqual(Object.keys(pm.ROLES_ALLOWED).sort());
  });

  const protectedKeys = Object.entries(pm.ROLES_ALLOWED).filter(([, r]) => r).map(([k]) => k);
  test.each(protectedKeys)('anonymous is rejected: %s', async (key) => {
    expect((await send(build(), key)).status).toBe(401);
  });

  const roleCases = Object.entries(pm.ROLES_ALLOWED).filter(([, r]) => r)
    .flatMap(([key, allowed]) => pm.ALL_ROLES.filter((r) => !allowed.includes(r)).map((role) => [key, role]));
  test.each(roleCases)('%s is forbidden for role %s', async (key, role) => {
    const app = build();
    const h = await login(app, pm.ROLE_USERS[role]);
    expect((await send(app, key, h)).status).toBe(403);
  });

  test.each(pm.READ_NOTE)('read note: %s -> note %i allowed=%s', async (actor, id, allowed) => {
    const app = build();
    const res = await request(app).get(`/notes/${id}`).set(await login(app, actor));
    if (allowed) expect(res.status).toBe(200); else expect(DENIED).toContain(res.status);
  });

  test.each(pm.DELETE_NOTE)('delete note: %s -> note %i allowed=%s', async (actor, id, allowed) => {
    const app = build();
    const res = await request(app).delete(`/admin/notes/${id}`).set(await login(app, actor));
    if (allowed) expect(res.status).toBe(204); else expect(DENIED).toContain(res.status);
  });

  test('list returns only the caller\'s notes', async () => {
    const app = build();
    const res = await request(app).get('/notes').set(await login(app, 'alice'));
    expect(res.body.map((n) => n.body)).toEqual(['alice private note']);
  });

  test('a denied delete did not delete', async () => {
    const app = build();
    await request(app).delete('/admin/notes/3').set(await login(app, 'adam'));
    expect((await request(app).get('/notes/3').set(await login(app, 'carol'))).status).toBe(200);
  });
});

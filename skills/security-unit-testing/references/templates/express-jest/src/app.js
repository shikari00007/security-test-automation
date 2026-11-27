'use strict';
// Tiny notes API with INTENTIONAL security bugs behind a fix toggle: createApp({ fixed: false }) is vulnerable.
// Synthetic only: test-only secret, plaintext demo passwords. Do not deploy.
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const SECRET = 'test-only-signing-key-0123456789-abcdef';
const MAX_FAILED = 5;
const USERS = {
  alice: { password: 'pw-alice-test', role: 'member', tenant: 'tenant-a' },
  bob: { password: 'pw-bob-test', role: 'member', tenant: 'tenant-a' },
  carol: { password: 'pw-carol-test', role: 'member', tenant: 'tenant-b' },
  adam: { password: 'pw-adam-test', role: 'admin', tenant: 'tenant-a' },
};

const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function createApp({ fixed = true, logger = console } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '10kb' }));
  const notes = new Map([
    [1, { id: 1, owner: 'alice', tenant: 'tenant-a', body: 'alice private note' }],
    [2, { id: 2, owner: 'bob', tenant: 'tenant-a', body: 'bob private note' }],
    [3, { id: 3, owner: 'carol', tenant: 'tenant-b', body: 'carol private note' }],
  ]);
  const revoked = new Set();
  const failures = new Map();
  let nextId = 4;

  if (fixed) {
    app.use((req, res, next) => {
      res.set('X-Content-Type-Options', 'nosniff');
      res.set('Cache-Control', 'no-store');
      res.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
      next();
    });
  }

  const auth = (req, res, next) => {
    const h = req.get('authorization') || '';
    if (!h.startsWith('Bearer ')) return res.status(401).json({ error: 'authentication required' });
    try {
      req.user = jwt.verify(h.slice(7), SECRET, { algorithms: ['HS256'] });
    } catch (e) {
      return res.status(401).json({ error: 'invalid token' });
    }
    if (fixed && revoked.has(req.user.jti)) return res.status(401).json({ error: 'invalid token' });
    next();
  };

  app.post('/login', (req, res) => {
    const { username, password } = req.body || {};
    if (fixed && (failures.get(username) || 0) >= MAX_FAILED) return res.status(429).json({ error: 'too many attempts' });
    const u = Object.prototype.hasOwnProperty.call(USERS, username) ? USERS[username] : null;
    if (!u || u.password !== password) {
      failures.set(username, (failures.get(username) || 0) + 1);
      if (fixed) logger.warn(`login failed user=${username}`);
      else logger.warn(`login failed user=${username} password=${password}`); // BUG: secret in log
      return res.status(401).json({ error: 'invalid credentials' });
    }
    failures.delete(username);
    const token = jwt.sign({ sub: username, role: u.role, tenant: u.tenant, jti: crypto.randomUUID() }, SECRET,
      { algorithm: 'HS256', expiresIn: 900 });
    res.json({ access_token: token });
  });

  app.post('/logout', auth, (req, res) => {
    if (fixed) revoked.add(req.user.jti);
    res.status(204).end();
  });

  app.get('/notes', auth, (req, res) => {
    const all = [...notes.values()];
    // BUG (vulnerable): every tenant's notes
    res.json((fixed ? all.filter((n) => n.owner === req.user.sub) : all).map(({ id, body }) => ({ id, body })));
  });

  app.post('/notes', auth, (req, res) => {
    const body = req.body && req.body.body;
    if (fixed && (typeof body !== 'string' || body.length < 1 || body.length > 1000)) {
      return res.status(422).json({ error: 'invalid note' });
    }
    const n = { id: nextId++, owner: req.user.sub, tenant: req.user.tenant, body };
    notes.set(n.id, n);
    res.status(201).json({ id: n.id, body: n.body });
  });

  const lookup = (req, res) => {
    const n = notes.get(Number(req.params.id));
    if (!n) { res.status(404).json({ error: 'not found' }); return null; }
    // BUG (vulnerable): no owner / tenant check (IDOR)
    if (fixed) {
      const ok = n.owner === req.user.sub || (req.user.role === 'admin' && n.tenant === req.user.tenant);
      if (!ok) { res.status(404).json({ error: 'not found' }); return null; }
    }
    return n;
  };

  app.get('/notes/:id', auth, (req, res) => {
    const n = lookup(req, res);
    if (n) res.json({ id: n.id, owner: n.owner, body: n.body });
  });

  app.get('/notes/:id/html', auth, (req, res) => {
    const n = lookup(req, res);
    if (!n) return;
    const body = fixed ? escapeHtml(n.body) : n.body; // BUG (vulnerable): stored data rendered unescaped
    res.type('html').send(`<p>${body}</p>`);
  });

  app.delete('/admin/notes/:id', auth, (req, res) => {
    const n = notes.get(Number(req.params.id));
    if (fixed) { // BUG (vulnerable): no role check, no tenant check
      if (req.user.role !== 'admin') return res.status(403).json({ error: 'forbidden' });
      if (!n || n.tenant !== req.user.tenant) return res.status(404).json({ error: 'not found' });
    }
    if (!n) return res.status(404).json({ error: 'not found' });
    notes.delete(n.id);
    res.status(204).end();
  });

  // error handler: no stack traces or internals to the client in the fixed variant
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (fixed) return res.status(err.status === 400 ? 400 : 500).json({ error: err.status === 400 ? 'bad request' : 'internal error' });
    res.status(err.status || 500).json({ error: err.message, stack: err.stack });
  });
  return app;
}

module.exports = { createApp, SECRET, USERS };

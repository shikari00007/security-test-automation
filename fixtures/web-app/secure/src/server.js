'use strict';
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const { execFile } = require('child_process');
const crypto = require('crypto');
const https = require('https');
const bcrypt = require('bcrypt');

const app = express();
const ALLOWED_ORIGINS = ['https://app.example.org'];

app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax' }
}));

app.post('/login', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie('session_id', token, { httpOnly: true, secure: true, sameSite: 'strict' });
  res.json({ ok: true });
});

app.get('/ping', (req, res) => {
  execFile('ping', ['-c', '1', req.query.host], (err, out) => res.send(out));
});

app.post('/calc', (req, res) => {
  const n = Number.parseFloat(req.body.value);
  res.json({ result: n * 2 });
});

const SAFE_TARGETS = { home: '/', account: '/account' };
app.get('/go', (req, res) => {
  const target = SAFE_TARGETS[req.query.to] || '/';
  res.redirect(target);
});

app.get('/user', (req, db) => {
  db.query('SELECT * FROM users WHERE name = $1', [req.query.name]);
});

const agent = new https.Agent({ rejectUnauthorized: true });

async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

// eval( is only mentioned in this comment, not called
app.listen(3000);

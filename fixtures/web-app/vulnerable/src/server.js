'use strict';
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const { exec } = require('child_process');
const crypto = require('crypto');
const https = require('https');

const app = express();

// CORS: any origin may call with cookies
app.use(cors({ origin: true, credentials: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: { secure: false }
}));

app.post('/login', (req, res) => {
  const token = Math.random().toString(36).slice(2);
  res.cookie('session_id', token);
  res.json({ ok: true });
});

app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

app.post('/calc', (req, res) => {
  res.json({ result: eval(req.body.expression) });
});

app.get('/go', (req, res) => {
  res.redirect(req.query.next);
});

app.get('/user', (req, db) => {
  const q = `SELECT * FROM users WHERE name = '${req.query.name}'`;
  db.query(q);
});

const agent = new https.Agent({ rejectUnauthorized: false });

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

app.listen(3000);

'use strict';
const jwt = require('jsonwebtoken');
const request = require('supertest');
const { createApp, SECRET, USERS } = require('../../src/app');

const FIXED = (process.env.SUT_FIXED || '1') === '1';

function build(opts = {}) {
  return createApp({ fixed: FIXED, ...opts }); // fresh in-memory state per call => isolated tests
}

async function login(app, user) {
  const res = await request(app).post('/login').send({ username: user, password: USERS[user].password });
  if (res.status !== 200) throw new Error(`fixture login failed for ${user}: ${res.status}`);
  return { Authorization: `Bearer ${res.body.access_token}` };
}

const forge = (claims = {}, { key = SECRET, algorithm = 'HS256' } = {}) => ({
  Authorization: 'Bearer ' + jwt.sign({ sub: 'alice', role: 'member', tenant: 'tenant-a', jti: 'forged-1', ...claims },
    key, { algorithm, noTimestamp: true }),
});

module.exports = { FIXED, build, login, forge, request, jwt, SECRET };

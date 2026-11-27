'use strict';
// Single source of truth for the authorization matrix. Edit when you add an endpoint.
// null = public on purpose. Anonymous callers must get 401 on every non-null entry.
const ROLES_ALLOWED = {
  'POST /login': null,
  'POST /logout': ['member', 'admin'],
  'GET /notes': ['member', 'admin'],
  'POST /notes': ['member', 'admin'],
  'GET /notes/:id': ['member', 'admin'],
  'GET /notes/:id/html': ['member', 'admin'],
  'DELETE /admin/notes/:id': ['admin'],
};
const ROLE_USERS = { member: 'alice', admin: 'adam' };
const ALL_ROLES = ['member', 'admin'];
// [actor, note id, allowed]   notes: 1=alice/A, 2=bob/A, 3=carol/B
const READ_NOTE = [['alice', 1, true], ['alice', 2, false], ['alice', 3, false], ['carol', 1, false], ['adam', 1, true], ['adam', 3, false]];
const DELETE_NOTE = [['alice', 1, false], ['adam', 3, false], ['adam', 2, true]];
module.exports = { ROLES_ALLOWED, ROLE_USERS, ALL_ROLES, READ_NOTE, DELETE_NOTE };

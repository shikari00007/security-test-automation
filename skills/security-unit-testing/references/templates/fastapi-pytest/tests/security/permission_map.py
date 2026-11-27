"""Single source of truth for the authorization matrix tests.

Edit this file when you add an endpoint; test_authz_matrix.py generates the cases from it.
ROLES_ALLOWED: (METHOD, path template) -> set of roles that may call it (any authenticated
user has exactly one role). Anonymous callers must always get 401.
"""
ROLES_ALLOWED = {
    ("POST", "/login"): None,                       # None = public on purpose (documented here)
    ("POST", "/logout"): {"member", "admin"},
    ("GET", "/notes"): {"member", "admin"},
    ("POST", "/notes"): {"member", "admin"},
    ("GET", "/notes/search"): {"member", "admin"},
    ("GET", "/notes/{note_id}"): {"member", "admin"},   # plus ownership rules below
    ("DELETE", "/admin/notes/{note_id}"): {"admin"},
}
ROLE_USERS = {"member": "alice", "admin": "adam"}
ALL_ROLES = {"member", "admin"}

# Object-level rules: (actor, note id, expected: True = allowed)  notes: 1=alice/A, 2=bob/A, 3=carol/B
READ_NOTE = [
    ("alice", 1, True),    # owner
    ("alice", 2, False),   # same tenant, other owner
    ("alice", 3, False),   # other tenant
    ("carol", 1, False),   # other tenant
    ("adam", 1, True),     # tenant admin reads tenant-a note
    ("adam", 3, False),    # tenant admin must not cross tenants
]
DELETE_NOTE = [
    ("alice", 1, False),   # member, even own note: admin endpoint
    ("adam", 3, False),    # cross-tenant admin
    ("adam", 2, True),
]

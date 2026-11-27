import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest  # noqa: E402
import app as appmod  # noqa: E402


@pytest.fixture()
def client(tmp_path):
    path = tmp_path / "t.db"
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, email TEXT);
        CREATE TABLE invoices(id INTEGER PRIMARY KEY, owner_id INTEGER, total_cents INTEGER, note TEXT);
        INSERT INTO users VALUES (1,'Alice','alice@example.test'),(2,'Bob','bob@example.test');
        INSERT INTO invoices VALUES (10,1,5000,'<script>alert(1)</script>'),(20,2,700,'thanks');
        """
    )
    con.commit()
    con.close()
    appmod.app.config.update(DATABASE=str(path), TESTING=True)
    return appmod.app.test_client()


def login(client, uid):
    with client.session_transaction() as s:
        s["user_id"] = uid


def test_owner_can_view_invoice(client):
    login(client, 1)
    assert client.get("/invoices/10").status_code == 200

import json
import subprocess

from openai import OpenAI

client = OpenAI()

ALLOWED_COMMANDS = {
    "disk": ["df", "-h"],
    "uptime": ["uptime"],
}


def run_task(question):
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": question}],
        response_format={"type": "json_object"},
    )
    answer = resp.choices[0].message.content
    choice = json.loads(answer).get("action")
    if choice not in ALLOWED_COMMANDS:
        raise ValueError("unsupported action")
    return subprocess.run(ALLOWED_COMMANDS[choice], capture_output=True, check=False)


def lookup(question, db):
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": question}])
    term = resp.choices[0].message.content
    return db.execute("SELECT * FROM items WHERE name = ?", (term,)).fetchall()

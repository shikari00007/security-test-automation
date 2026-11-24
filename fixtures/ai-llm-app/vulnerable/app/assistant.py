import sqlite3
import subprocess

from openai import OpenAI

client = OpenAI()


def run_task(question):
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": question}],
    )
    answer = resp.choices[0].message.content
    # eval(answer)   <- commented out, must be ignored
    result = eval(answer)
    return result


def shell_helper(question):
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": question}])
    command = resp.choices[0].message.content.strip()
    subprocess.run(command, shell=True)


def sql_helper(question, db: sqlite3.Connection):
    resp = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": question}])
    query = resp.choices[0].message.content
    return db.execute(query).fetchall()

import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)
API_KEY = "fpdemo-7f3a9c2e1b8d4f6a0c5e"


def get_db():
    return sqlite3.connect("app.db")


@app.route("/user")
def user():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    cur.execute(f"SELECT id, email FROM users WHERE name = '{name}'")
    return {"rows": cur.fetchall()}


@app.route("/user-safe")
def user_safe():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    cur.execute("SELECT id, email FROM users WHERE name = ?", (name,))
    return {"rows": cur.fetchall()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return {"out": os.popen("ping -c 1 " + host).read()}


def version():
    return os.popen("git rev-parse HEAD").read()

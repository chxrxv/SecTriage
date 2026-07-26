"""Deliberately vulnerable minimal Flask app — used ONLY as a static-analysis test
fixture for SecTriage's accuracy evaluation (tests/run_eval.py). Do not deploy this.

Each vulnerable line is tagged with a trailing `# VULN: <pattern>` comment so the
ground-truth manifest (ground_truth.json) can be derived precisely from the source
instead of hand-counted line numbers. `# SAFE:` marks a true-negative case the
scanner should NOT flag. `# MISSED:` marks a deliberately-injected vulnerability
that the line-based scanner is expected to miss (multi-line construction) — this
keeps the measured recall honest rather than artificially perfect.
"""
import os
import pickle
import sqlite3

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")

# --- Hardcoded secrets ------------------------------------------------------
STRIPE_API_KEY = "REDACTED_FAKE_SECRET_NOT_A_REAL_KEY_00000"  # VULN: hardcoded_secret
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # VULN: hardcoded_secret
API_SECRET = os.environ.get("API_SECRET", "")  # SAFE: loaded from environment, not a literal


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")  # VULN: sql_injection
    return str(cursor.fetchall())


@app.route("/lookup")
def lookup():
    user_id = request.args.get("id", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # VULN: sql_injection
    return str(cursor.fetchone())


@app.route("/lookup_safe")
def lookup_safe():
    user_id = request.args.get("id", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # SAFE: parameterized query
    return str(cursor.fetchone())


@app.route("/comments")
def comments():
    post_id = request.args.get("post_id", "")
    conn = get_db()
    cursor = conn.cursor()
    query = "SELECT * FROM comments WHERE post_id = " + post_id  # MISSED: sql_injection (built on one line, executed on the next)
    cursor.execute(query)
    return str(cursor.fetchall())


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    return "<h1>Hello " + name + "</h1>"  # VULN: xss


@app.route("/load_config", methods=["POST"])
def load_config():
    config = pickle.loads(request.data)  # VULN: insecure_deserialization
    return str(config)


@app.route("/load_yaml", methods=["POST"])
def load_yaml():
    data = yaml.load(request.data)  # VULN: insecure_deserialization
    return str(data)


@app.route("/load_yaml_safe", methods=["POST"])
def load_yaml_safe():
    data = yaml.load(request.data, Loader=yaml.SafeLoader)  # SAFE: explicit SafeLoader
    return str(data)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    result = eval(expr)  # VULN: code_injection
    return str(result)


@app.route("/download")
def download():
    with open(os.path.join(UPLOAD_DIR, request.args["filename"]), "rb") as f:  # VULN: path_traversal
        return f.read()


@app.route("/download_safe")
def download_safe():
    from werkzeug.utils import secure_filename

    filename = secure_filename(request.args.get("filename", ""))
    path = os.path.join(UPLOAD_DIR, filename)  # SAFE: sanitized with secure_filename first
    with open(path, "rb") as f:
        return f.read()


@app.route("/fetch")
def fetch():
    target_url = request.args.get("url", "")
    resp = requests.get(target_url)  # VULN: ssrf
    return resp.text


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    os.system("ping -c 1 " + host)  # VULN: command_injection
    return "done"


@app.route("/admin/delete_user")  # VULN: missing_auth_check
def admin_delete_user():
    user_id = request.args.get("id", "")
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return "deleted"


@app.route("/profile")
def profile():
    from functools import wraps

    def login_required(f):
        @wraps(f)
        def wrapper(*a, **kw):
            return f(*a, **kw)

        return wrapper

    return "profile page"  # SAFE: not a sensitive route name, no finding expected


if __name__ == "__main__":
    app.run(debug=True)

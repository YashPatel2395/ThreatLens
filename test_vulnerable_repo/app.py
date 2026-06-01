"""
app.py — Intentionally vulnerable Flask application.

Vulnerabilities present (for scanner testing only):
  1. SQL injection via f-string query construction (line ~30)
  2. SQL injection via string concatenation (line ~42)
  3. Debug mode enabled (line ~70)
  4. Unsafe deserialization via pickle (line ~55)

DO NOT deploy this code. It exists solely to test that scanners detect
these patterns correctly.
"""
import pickle
import sqlite3

from flask import Flask, request

app = Flask(__name__)
# Vulnerability: debug mode left on in production code
app.config["DEBUG"] = True
app.config["SECRET_KEY"] = "hardcoded-secret-key-do-not-use"


def get_db():
    return sqlite3.connect("users.db")


# ---------------------------------------------------------------------------
# Vulnerability 1: SQL injection via f-string
# Semgrep rule: python.lang.security.audit.formatted-sql-query
# ---------------------------------------------------------------------------

@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE: user input interpolated directly into SQL query
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return str(rows)


# ---------------------------------------------------------------------------
# Vulnerability 2: SQL injection via string concatenation
# ---------------------------------------------------------------------------

@app.route("/search")
def search_users():
    username = request.args.get("username", "")
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABLE: string concatenation in SQL
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return str(rows)


# ---------------------------------------------------------------------------
# Vulnerability 3: Unsafe deserialization
# ---------------------------------------------------------------------------

@app.route("/load", methods=["POST"])
def load_data():
    raw = request.get_data()
    # VULNERABLE: pickle.loads on untrusted input enables arbitrary code execution
    data = pickle.loads(raw)
    return str(data)


# ---------------------------------------------------------------------------
# Entry point with debug=True
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # VULNERABLE: debug=True exposes the Werkzeug debugger in production
    app.run(host="0.0.0.0", debug=True)

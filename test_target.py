"""Minimal vulnerable test server for DAST scanner local testing."""
from flask import Flask, request, make_response

app = Flask(__name__)

@app.route("/")
def index():
    return """<html><head><title>Test App</title></head><body>
    <h1>DAST Test Target</h1>
    <a href="/search?q=test">Search</a>
    <a href="/user?id=1">User Profile</a>
    <a href="/login">Login</a>
    <a href="/api/data">API</a>
    <form action="/search" method="GET">
        <input name="q" type="text" placeholder="Search...">
        <button type="submit">Go</button>
    </form>
    </body></html>"""

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Reflected XSS (intentionally vulnerable)
    return f"<html><body><h2>Results for: {q}</h2><p>No results.</p></body></html>"

@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    return f'{{"user_id": {uid}, "name": "TestUser", "email": "test@example.com"}}'

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return '{"status": "ok", "token": "fake-jwt-token"}'
    return """<html><body><form method="POST" action="/login">
    <input name="username" type="text">
    <input name="password" type="password">
    <button type="submit">Login</button>
    </form></body></html>"""

@app.route("/api/data")
def api_data():
    resp = make_response('{"items": [1,2,3]}')
    resp.headers["Content-Type"] = "application/json"
    resp.headers["X-Powered-By"] = "Express"  # Fake header for fingerprinting
    return resp

@app.route("/admin")
def admin():
    return "<html><body><h1>Admin Panel</h1></body></html>", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9999, debug=False)

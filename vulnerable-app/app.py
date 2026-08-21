import os
import platform
import sqlite3

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

from database import get_db

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "pentest-lab-dev-secret"

# INTENTIONAL VULN #11: guvenlik header'lari (CSP / X-Frame-Options / HSTS / X-Content-Type-Options)
# hicbir yerde eklenmiyor -- bu bilincli bir eksiklik, after_request hook'u yok.
# INTENTIONAL VULN #11b: session cookie flag'leri bilerek zayif birakildi.
app.config["SESSION_COOKIE_HTTPONLY"] = False
app.config["SESSION_COOKIE_SAMESITE"] = None
app.config["SESSION_COOKIE_SECURE"] = False


def current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return row


@app.route("/")
def index():
    conn = get_db()
    products = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    return render_template("index.html", products=products, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # INTENTIONAL VULN #2 & #8: sorgu raw string ile kuruluyor + login denemesinde rate-limit yok.
        # ' OR '1'='1 gibi bir payload WHERE kosulunu daima True yaparak auth'u bypass eder.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        conn = get_db()
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.OperationalError as exc:
            conn.close()
            return render_template("login.html", error=f"Veritabani hatasi: {exc}"), 500
        conn.close()

        if row:
            session["user_id"] = row["id"]
            return redirect(url_for("index"))
        error = "Kullanici adi veya sifre hatali."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/search")
def search():
    q = request.args.get("q", "")
    results = []
    db_error = None
    if q:
        # INTENTIONAL VULN #1: LIKE sorgusu string formatlama ile kuruluyor (SQL Injection).
        query = f"SELECT * FROM products WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
        conn = get_db()
        try:
            results = conn.execute(query).fetchall()
        except sqlite3.OperationalError as exc:
            db_error = str(exc)
        conn.close()
    # INTENTIONAL VULN #4: q parametresi search.html icinde |safe ile escape'siz basiliyor (reflected XSS).
    return render_template("search.html", q=q, results=results, db_error=db_error, user=current_user())


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    if request.method == "POST":
        author = request.form.get("author", "misafir")
        message = request.form.get("message", "")
        conn = get_db()
        conn.execute("INSERT INTO guestbook (author, message) VALUES (?, ?)", (author, message))
        conn.commit()
        conn.close()
        return redirect(url_for("guestbook"))
    conn = get_db()
    entries = conn.execute("SELECT * FROM guestbook ORDER BY id DESC").fetchall()
    conn.close()
    # INTENTIONAL VULN #3: guestbook.html mesaji |safe ile escape'siz render eder (stored XSS).
    return render_template("guestbook.html", entries=entries, user=current_user())


@app.route("/profile/<int:user_id>")
def profile(user_id):
    if not current_user():
        return redirect(url_for("login"))
    conn = get_db()
    # INTENTIONAL VULN #6: sahiplik kontrolu yok -- session'daki degil, URL'deki id kullaniliyor (IDOR).
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return "Kullanici bulunamadi", 404
    return render_template("profile.html", profile_user=row, user=current_user())


@app.route("/profile/update", methods=["POST"])
def profile_update():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # INTENTIONAL VULN #5: CSRF token kontrolu yok -- baska bir siteden forgeable POST kabul ediliyor.
    new_email = request.form.get("email", user["email"])
    conn = get_db()
    conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user["id"]))
    conn.commit()
    conn.close()
    return redirect(url_for("profile", user_id=user["id"]))


@app.route("/admin")
def admin():
    # INTENTIONAL VULN #7: sadece login kontrolu var, role == 'admin' kontrolu yok (broken access control).
    if not current_user():
        return redirect(url_for("login"))
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return render_template("admin.html", users=users, user=current_user())


@app.route("/admin-secure")
def admin_secure():
    # KONTROL GRUBU -- bilerek GUVENLI: /admin'in aksine role == 'admin' de kontrol
    # ediliyor. Scanner'in "her admin-benzeri path'i kor kore isaretlemedigini",
    # gercekten dogru korunan bir endpoint'i AYIRT edebildigini kanitlamak icin var.
    user = current_user()
    if not user or user["role"] != "admin":
        return "Forbidden: bu sayfa sadece admin rolundeki kullanicilar icindir.", 403
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return render_template("admin.html", users=users, user=user)


@app.route("/tools/ping", methods=["GET", "POST"])
def tools_ping():
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        flag = "-n" if platform.system().lower() == "windows" else "-c"
        # INTENTIONAL VULN #9: host degeri sanitize edilmeden shell'e gidiyor (command injection).
        output = os.popen(f"ping {flag} 1 {host}").read()
    return render_template("ping.html", output=output, user=current_user())


@app.route("/uploads/")
def uploads_listing():
    upload_dir = os.path.join(BASE_DIR, "static", "uploads")
    # INTENTIONAL VULN #12: klasor icerigi dogrudan listeleniyor (directory listing).
    files = os.listdir(upload_dir)
    items = "".join(f'<li><a href="/static/uploads/{f}">{f}</a></li>' for f in files)
    return f"<h2>Index of /uploads/</h2><ul>{items}</ul>"


# ---------------------------------------------------------------------------
# Mobil uygulamanin konustugu JSON/REST API (mobile backend simulasyonu)
# ---------------------------------------------------------------------------


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    # INTENTIONAL VULN #13 & #17: web login ile ayni SQLi deseni + rate-limit yok, JSON API'de.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    conn = get_db()
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.OperationalError as exc:
        conn.close()
        return jsonify({"error": f"db_error: {exc}"}), 500
    conn.close()
    if row:
        session["user_id"] = row["id"]
        return jsonify({"status": "ok", "user_id": row["id"]})
    return jsonify({"status": "error", "message": "invalid credentials"}), 401


@app.route("/api/profile/<int:user_id>")
def api_profile(user_id):
    if not current_user():
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    # INTENTIONAL VULN #14: sahiplik kontrolu yok (BOLA / IDOR).
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not_found"}), 404
    # INTENTIONAL VULN #15: password ve notes gibi client'in ihtiyaci olmadigi alanlar da donuyor
    # (excessive data exposure).
    return jsonify(
        {
            "id": row["id"],
            "username": row["username"],
            "email": row["email"],
            "role": row["role"],
            "password": row["password"],
            "notes": row["notes"],
        }
    )


@app.route("/api/admin/users")
def api_admin_users():
    # INTENTIONAL VULN #16: sadece login kontrolu var, role kontrolu yok (broken access control).
    if not current_user():
        return jsonify({"error": "unauthorized"}), 401
    conn = get_db()
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin-secure/users")
def api_admin_secure_users():
    # KONTROL GRUBU -- bilerek GUVENLI: /api/admin/users'in aksine role == 'admin'
    # de kontrol ediliyor. Scanner'in dogru korunan API endpoint'lerini yanlislikla
    # bulgu olarak isaretlemedigini kanitlamak icin var.
    user = current_user()
    if not user or user["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    conn = get_db()
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

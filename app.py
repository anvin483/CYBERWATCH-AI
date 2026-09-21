import os
import secrets
import time
from collections import defaultdict, deque

from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for, jsonify
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

from database.models import create_tables
from api.dashboard import dashboard_bp
from globe.globe_api import globe_bp

from services.feed_manager import seed_database
from services.scheduler import start_scheduler
from services.audit import record, recent
from database.db import get_connection


load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-this-secret")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED", "false").lower() == "true",
)
_initialized = False
_rate_buckets = defaultdict(deque)

app.register_blueprint(dashboard_bp)
app.register_blueprint(globe_bp)


def _password_hash():
    configured_hash = os.environ.get("ADMIN_PASSWORD_HASH")
    if configured_hash:
        return configured_hash
    return generate_password_hash(os.environ.get("ADMIN_PASSWORD", "cyberwatch"))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("authenticated"):
            return view(*args, **kwargs)
        if request.path.startswith("/api/"):
            return {"error": "authentication required"}, 401
        return redirect(url_for("login"))
    return wrapped


@app.before_request
def protect_routes():
    public_paths = {"/login", "/static"}
    if request.path == "/login" or request.path.startswith("/static/"):
        return None
    if request.path == "/api/sensor/ingest":
        if not _rate_limit("sensor:" + request.remote_addr, 120, 60):
            return jsonify({"error": "rate limit exceeded"}), 429
        return None
    if request.path.startswith("/api/") and not _rate_limit("api:" + request.remote_addr, 240, 60):
        return jsonify({"error": "rate limit exceeded"}), 429
    if request.method in {"POST", "PATCH", "PUT", "DELETE"} and session.get("authenticated"):
        token = request.headers.get("X-CSRF-Token", "")
        if not token or not secrets.compare_digest(token, session.get("csrf_token", "")):
            return jsonify({"error": "csrf validation failed"}), 403
    if not session.get("authenticated"):
        if request.path.startswith("/api/"):
            return {"error": "authentication required"}, 401
        return redirect(url_for("login"))
    return None


def _rate_limit(key, maximum, window):
    redis_url = os.environ.get("REDIS_URL")
    if redis_url:
        try:
            from redis import Redis
            redis = Redis.from_url(redis_url, decode_responses=True)
            redis_key = "cyberwatch:rate:" + key
            count = redis.incr(redis_key)
            if count == 1:
                redis.expire(redis_key, window)
            return count <= maximum
        except (ImportError, OSError, ValueError):
            pass
    now = time.monotonic()
    bucket = _rate_buckets[key]
    while bucket and now - bucket[0] > window:
        bucket.popleft()
    if len(bucket) >= maximum:
        return False
    bucket.append(now)
    return True


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        expected_user = os.environ.get("ADMIN_USERNAME", "admin")
        analyst_user = os.environ.get("ANALYST_USERNAME")
        analyst_password = os.environ.get("ANALYST_PASSWORD")
        valid_admin = username == expected_user and check_password_hash(_password_hash(), password)
        valid_analyst = analyst_user and analyst_password and username == analyst_user and password == analyst_password
        if valid_admin or valid_analyst:
            session["authenticated"] = True
            session["username"] = username
            session["role"] = "analyst" if valid_analyst else os.environ.get("ADMIN_ROLE", "admin")
            session["csrf_token"] = secrets.token_urlsafe(32)
            record(username, "login", "session", {"role": session["role"]}, request.remote_addr)
            return redirect(url_for("dashboard"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():

    return render_template(
        "dashboard.html", csrf_token=session.get("csrf_token", "")
    )


@app.route("/api/ops/health")
def ops_health():
    started = time.perf_counter()
    conn = get_connection()
    db_ok = True
    try:
        conn.execute("SELECT 1").fetchone()
        counts = {table: conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()["count"] for table in ("events", "attacks", "incidents")}
        sensors = [dict(row) for row in conn.execute("SELECT sensor_id, last_seen, event_count, source FROM sensor_heartbeats ORDER BY last_seen DESC LIMIT 20").fetchall()]
    except Exception:
        db_ok, counts, sensors = False, {}, []
    finally:
        conn.close()
    return jsonify({"status": "ok" if db_ok else "degraded", "database": {"status": "online" if db_ok else "offline", "counts": counts}, "sensors": sensors, "apiLatencyMs": round((time.perf_counter() - started) * 1000, 2), "checkedAt": time.time()})


@app.route("/api/ops/audit")
def ops_audit():
    if session.get("role", "admin") != "admin":
        return jsonify({"error": "admin role required"}), 403
    return jsonify(recent())


def initialize_app():
    global _initialized
    if _initialized:
        return
    print("\nCYBERWATCH AI STARTED\n")

    if os.environ.get("FLASK_ENV") == "production" and app.secret_key in {"dev-change-this-secret", "change-this-secret-in-production"}:
        raise RuntimeError("A strong SECRET_KEY is required in production")

    create_tables()

    seed_database()

    start_scheduler()
    _initialized = True


initialize_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "1") == "1",
        use_reloader=False
    )

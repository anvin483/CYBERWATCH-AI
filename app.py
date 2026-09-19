import os

from flask import Flask, redirect, render_template, request, session, url_for
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

from database.models import create_tables
from api.dashboard import dashboard_bp
from globe.globe_api import globe_bp

from services.feed_manager import seed_database
from services.scheduler import start_scheduler


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-this-secret")
_initialized = False

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
    if not session.get("authenticated"):
        if request.path.startswith("/api/"):
            return {"error": "authentication required"}, 401
        return redirect(url_for("login"))
    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        expected_user = os.environ.get("ADMIN_USERNAME", "admin")
        if username == expected_user and check_password_hash(_password_hash(), password):
            session["authenticated"] = True
            session["username"] = username
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
        "dashboard.html"
    )


def initialize_app():
    global _initialized
    if _initialized:
        return
    print("\nCYBERWATCH AI STARTED\n")

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

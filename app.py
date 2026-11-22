import os
import re
import hmac
import secrets
import sqlite3
import logging
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
RENDER_API_KEY = os.environ.get("RENDER_API_KEY", "")
DATABASE_PATH = os.environ.get("DATABASE_PATH", "/var/data/shanto.db")

RENDER_API = "https://api.render.com/v1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shanto-hosting")

if not app.secret_key or not ADMIN_PASSWORD:
    raise RuntimeError("SECRET_KEY and ADMIN_PASSWORD must be configured.")

os.makedirs(os.path.dirname(DATABASE_PATH) or ".", exist_ok=True)


def db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                repo TEXT NOT NULL,
                service_id TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_db()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        received = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, received):
            abort(403)


def render_request(method, path, payload=None):
    if not RENDER_API_KEY:
        raise RuntimeError("RENDER_API_KEY is not configured.")

    response = requests.request(
        method,
        f"{RENDER_API}{path}",
        headers={
            "Authorization": f"Bearer {RENDER_API_KEY}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=25,
    )

    if not response.ok:
        logger.error(
            "Render API error: %s %s",
            response.status_code,
            response.text[:500],
        )
        raise RuntimeError(
            f"Render API returned HTTP {response.status_code}."
        )

    if response.status_code == 204 or not response.text:
        return {}

    return response.json()


def valid_github_repo(value):
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        return False

    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) != 2:
        return False

    return all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts)


def get_projects():
    with db() as con:
        return con.execute(
            "SELECT * FROM projects ORDER BY id DESC"
        ).fetchall()


def get_project(project_id):
    with db() as con:
        return con.execute(
            "SELECT * FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()


@app.route("/")
def home():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user_ok = hmac.compare_digest(username, ADMIN_USERNAME)
        pass_ok = hmac.compare_digest(password, ADMIN_PASSWORD)

        if user_ok and pass_ok:
            session.clear()
            session["logged_in"] = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))

        flash("Login তথ্য সঠিক নয়।", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    projects = get_projects()
    cards = []

    for project in projects:
        status = "Unknown"
        service_name = project["name"]
        suspended = None
        error = None

        try:
            data = render_request(
                "GET",
                f"/services/{project['service_id']}"
            )

            service = data.get("service", data)
            service_name = service.get("name") or service_name
            suspended = service.get("suspended")

            if suspended == "suspended":
                status = "Stopped"
            elif suspended == "not_suspended":
                status = "Not suspended"
            else:
                status = service.get("status", "Available")

        except Exception as exc:
            error = str(exc)
            status = "Unavailable"

        cards.append({
            "project": project,
            "status": status,
            "service_name": service_name,
            "error": error,
        })

    return render_template(
        "dashboard.html",
        projects=cards,
        total=len(cards),
    )


@app.route("/projects/add", methods=["POST"])
@login_required
def add_project():
    name = request.form.get("name", "").strip()
    repo = request.form.get("repo", "").strip()
    service_id = request.form.get("service_id", "").strip()

    if not name or len(name) > 60:
        flash("Project নাম ১ থেকে ৬০ অক্ষরের মধ্যে হতে হবে।", "error")
        return redirect(url_for("dashboard"))

    if not valid_github_repo(repo):
        flash("সঠিক GitHub Repository URL দিন।", "error")
        return redirect(url_for("dashboard"))

    if not re.fullmatch(r"srv-[A-Za-z0-9]+", service_id):
        flash("Render Service ID সঠিক নয়।", "error")
        return redirect(url_for("dashboard"))

    try:
        # Verify that this Render service is accessible by this API key.
        render_request("GET", f"/services/{service_id}")

        with db() as con:
            con.execute(
                """
                INSERT INTO projects (name, repo, service_id)
                VALUES (?, ?, ?)
                """,
                (name, repo, service_id),
            )

        flash("Project Dashboard-এ যোগ হয়েছে।", "success")

    except sqlite3.IntegrityError:
        flash("এই Render Service ID আগে থেকেই যোগ করা হয়েছে।", "error")
    except Exception as exc:
        flash(f"Project যোগ করা যায়নি: {exc}", "error")

    return redirect(url_for("dashboard"))


@app.route("/projects/<int:project_id>/action", methods=["POST"])
@login_required
def project_action(project_id):
    project = get_project(project_id)
    if not project:
        abort(404)

    action = request.form.get("action", "")
    service_id = project["service_id"]

    endpoints = {
        "restart": ("POST", f"/services/{service_id}/restart", None),
        "stop": ("POST", f"/services/{service_id}/suspend", None),
        "resume": ("POST", f"/services/{service_id}/resume", None),
        "deploy": (
            "POST",
            f"/services/{service_id}/deploys",
            {"clearCache": "do_not_clear"},
        ),
    }

    if action not in endpoints:
        abort(400)

    method, path, payload = endpoints[action]

    try:
        render_request(method, path, payload)
        flash(f"{action.title()} অনুরোধ Render-এ পাঠানো হয়েছে।", "success")
    except Exception as exc:
        flash(f"কাজটি সম্পন্ন হয়নি: {exc}", "error")

    return redirect(url_for("dashboard"))


@app.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id):
    with db() as con:
        con.execute(
            "DELETE FROM projects WHERE id = ?",
            (project_id,),
        )

    # This removes only the dashboard record.
    # It does NOT delete the actual Render service.
    flash("Dashboard থেকে Project record মুছে ফেলা হয়েছে।", "success")
    return redirect(url_for("dashboard"))


@app.route("/health")
def health():
    return {"status": "ok", "app": "SHANTO BOT HOSTING V3"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))import os
import re
import hmac
import secrets
import sqlite3
import logging
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
RENDER_API_KEY = os.environ.get("RENDER_API_KEY", "")
DATABASE_PATH = os.environ.get("DATABASE_PATH", "/var/data/shanto.db")

RENDER_API = "https://api.render.com/v1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shanto-hosting")

if not app.secret_key or not ADMIN_PASSWORD:
    raise RuntimeError("SECRET_KEY and ADMIN_PASSWORD must be configured.")

os.makedirs(os.path.dirname(DATABASE_PATH) or ".", exist_ok=True)


def db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                repo TEXT NOT NULL,
                service_id TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_db()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        received = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, received):
            abort(403)


def render_request(method, path, payload=None):
    if not RENDER_API_KEY:
        raise RuntimeError("RENDER_API_KEY is not configured.")

    response = requests.request(
        method,
        f"{RENDER_API}{path}",
        headers={
            "Authorization": f"Bearer {RENDER_API_KEY}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=25,
    )

    if not response.ok:
        logger.error(
            "Render API error: %s %s",
            response.status_code,
            response.text[:500],
        )
        raise RuntimeError(
            f"Render API returned HTTP {response.status_code}."
        )

    if response.status_code == 204 or not response.text:
        return {}

    return response.json()


def valid_github_repo(value):
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        return False

    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) != 2:
        return False

    return all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts)


def get_projects():
    with db() as con:
        return con.execute(
            "SELECT * FROM projects ORDER BY id DESC"
        ).fetchall()


def get_project(project_id):
    with db() as con:
        return con.execute(
            "SELECT * FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()


@app.route("/")
def home():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user_ok = hmac.compare_digest(username, ADMIN_USERNAME)
        pass_ok = hmac.compare_digest(password, ADMIN_PASSWORD)

        if user_ok and pass_ok:
            session.clear()
            session["logged_in"] = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))

        flash("Login তথ্য সঠিক নয়।", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    projects = get_projects()
    cards = []

    for project in projects:
        status = "Unknown"
        service_name = project["name"]
        suspended = None
        error = None

        try:
            data = render_request(
                "GET",
                f"/services/{project['service_id']}"
            )

            service = data.get("service", data)
            service_name = service.get("name") or service_name
            suspended = service.get("suspended")

            if suspended == "suspended":
                status = "Stopped"
            elif suspended == "not_suspended":
                status = "Not suspended"
            else:
                status = service.get("status", "Available")

        except Exception as exc:
            error = str(exc)
            status = "Unavailable"

        cards.append({
            "project": project,
            "status": status,
            "service_name": service_name,
            "error": error,
        })

    return render_template(
        "dashboard.html",
        projects=cards,
        total=len(cards),
    )


@app.route("/projects/add", methods=["POST"])
@login_required
def add_project():
    name = request.form.get("name", "").strip()
    repo = request.form.get("repo", "").strip()
    service_id = request.form.get("service_id", "").strip()

    if not name or len(name) > 60:
        flash("Project নাম ১ থেকে ৬০ অক্ষরের মধ্যে হতে হবে।", "error")
        return redirect(url_for("dashboard"))

    if not valid_github_repo(repo):
        flash("সঠিক GitHub Repository URL দিন।", "error")
        return redirect(url_for("dashboard"))

    if not re.fullmatch(r"srv-[A-Za-z0-9]+", service_id):
        flash("Render Service ID সঠিক নয়।", "error")
        return redirect(url_for("dashboard"))

    try:
        # Verify that this Render service is accessible by this API key.
        render_request("GET", f"/services/{service_id}")

        with db() as con:
            con.execute(
                """
                INSERT INTO projects (name, repo, service_id)
                VALUES (?, ?, ?)
                """,
                (name, repo, service_id),
            )

        flash("Project Dashboard-এ যোগ হয়েছে।", "success")

    except sqlite3.IntegrityError:
        flash("এই Render Service ID আগে থেকেই যোগ করা হয়েছে।", "error")
    except Exception as exc:
        flash(f"Project যোগ করা যায়নি: {exc}", "error")

    return redirect(url_for("dashboard"))


@app.route("/projects/<int:project_id>/action", methods=["POST"])
@login_required
def project_action(project_id):
    project = get_project(project_id)
    if not project:
        abort(404)

    action = request.form.get("action", "")
    service_id = project["service_id"]

    endpoints = {
        "restart": ("POST", f"/services/{service_id}/restart", None),
        "stop": ("POST", f"/services/{service_id}/suspend", None),
        "resume": ("POST", f"/services/{service_id}/resume", None),
        "deploy": (
            "POST",
            f"/services/{service_id}/deploys",
            {"clearCache": "do_not_clear"},
        ),
    }

    if action not in endpoints:
        abort(400)

    method, path, payload = endpoints[action]

    try:
        render_request(method, path, payload)
        flash(f"{action.title()} অনুরোধ Render-এ পাঠানো হয়েছে।", "success")
    except Exception as exc:
        flash(f"কাজটি সম্পন্ন হয়নি: {exc}", "error")

    return redirect(url_for("dashboard"))


@app.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id):
    with db() as con:
        con.execute(
            "DELETE FROM projects WHERE id = ?",
            (project_id,),
        )

    # This removes only the dashboard record.
    # It does NOT delete the actual Render service.
    flash("Dashboard থেকে Project record মুছে ফেলা হয়েছে।", "success")
    return redirect(url_for("dashboard"))


@app.route("/health")
def health():
    return {"status": "ok", "app": "SHANTO BOT HOSTING V3"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))import os
import re
import hmac
import secrets
import sqlite3
import logging
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
RENDER_API_KEY = os.environ.get("RENDER_API_KEY", "")
DATABASE_PATH = os.environ.get("DATABASE_PATH", "/var/data/shanto.db")

RENDER_API = "https://api.render.com/v1"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shanto-hosting")

if not app.secret_key or not ADMIN_PASSWORD:
    raise RuntimeError("SECRET_KEY and ADMIN_PASSWORD must be configured.")

os.makedirs(os.path.dirname(DATABASE_PATH) or ".", exist_ok=True)


def db():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                repo TEXT NOT NULL,
                service_id TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_db()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_post_requests():
    if request.method == "POST":
        expected = session.get("csrf_token", "")
        received = request.form.get("csrf_token", "")
        if not expected or not hmac.compare_digest(expected, received):
            abort(403)


def render_request(method, path, payload=None):
    if not RENDER_API_KEY:
        raise RuntimeError("RENDER_API_KEY is not configured.")

    response = requests.request(
        method,
        f"{RENDER_API}{path}",
        headers={
            "Authorization": f"Bearer {RENDER_API_KEY}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=25,
    )

    if not response.ok:
        logger.error(
            "Render API error: %s %s",
            response.status_code,
            response.text[:500],
        )
        raise RuntimeError(
            f"Render API returned HTTP {response.status_code}."
        )

    if response.status_code == 204 or not response.text:
        return {}

    return response.json()


def valid_github_repo(value):
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        return False

    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) != 2:
        return False

    return all(re.fullmatch(r"[A-Za-z0-9_.-]+", p) for p in parts)


def get_projects():
    with db() as con:
        return con.execute(
            "SELECT * FROM projects ORDER BY id DESC"
        ).fetchall()


def get_project(project_id):
    with db() as con:
        return con.execute(
            "SELECT * FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()


@app.route("/")
def home():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        user_ok = hmac.compare_digest(username, ADMIN_USERNAME)
        pass_ok = hmac.compare_digest(password, ADMIN_PASSWORD)

        if user_ok and pass_ok:
            session.clear()
            session["logged_in"] = True
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))

        flash("Login তথ্য সঠিক নয়।", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    projects = get_projects()
    cards = []

    for project in projects:
        status = "Unknown"
        service_name = project["name"]
        suspended = None
        error = None

        try:
            data = render_request(
                "GET",
                f"/services/{project['service_id']}"
            )

            service = data.get("service", data)
            service_name = service.get("name") or service_name
            suspended = service.get("suspended")

            if suspended == "suspended":
                status = "Stopped"
            elif suspended == "not_suspended":
                status = "Not suspended"
            else:
                status = service.get("status", "Available")

        except Exception as exc:
            error = str(exc)
            status = "Unavailable"

        cards.append({
            "project": project,
            "status": status,
            "service_name": service_name,
            "error": error,
        })

    return render_template(
        "dashboard.html",
        projects=cards,
        total=len(cards),
    )


@app.route("/projects/add", methods=["POST"])
@login_required
def add_project():
    name = request.form.get("name", "").strip()
    repo = request.form.get("repo", "").strip()
    service_id = request.form.get("service_id", "").strip()

    if not name or len(name) > 60:
        flash("Project নাম ১ থেকে ৬০ অক্ষরের মধ্যে হতে হবে।", "error")
        return redirect(url_for("dashboard"))

    if not valid_github_repo(repo):
        flash("সঠিক GitHub Repository URL দিন।", "error")
        return redirect(url_for("dashboard"))

    if not re.fullmatch(r"srv-[A-Za-z0-9]+", service_id):
        flash("Render Service ID সঠিক নয়।", "error")
        return redirect(url_for("dashboard"))

    try:
        # Verify that this Render service is accessible by this API key.
        render_request("GET", f"/services/{service_id}")

        with db() as con:
            con.execute(
                """
                INSERT INTO projects (name, repo, service_id)
                VALUES (?, ?, ?)
                """,
                (name, repo, service_id),
            )

        flash("Project Dashboard-এ যোগ হয়েছে।", "success")

    except sqlite3.IntegrityError:
        flash("এই Render Service ID আগে থেকেই যোগ করা হয়েছে।", "error")
    except Exception as exc:
        flash(f"Project যোগ করা যায়নি: {exc}", "error")

    return redirect(url_for("dashboard"))


@app.route("/projects/<int:project_id>/action", methods=["POST"])
@login_required
def project_action(project_id):
    project = get_project(project_id)
    if not project:
        abort(404)

    action = request.form.get("action", "")
    service_id = project["service_id"]

    endpoints = {
        "restart": ("POST", f"/services/{service_id}/restart", None),
        "stop": ("POST", f"/services/{service_id}/suspend", None),
        "resume": ("POST", f"/services/{service_id}/resume", None),
        "deploy": (
            "POST",
            f"/services/{service_id}/deploys",
            {"clearCache": "do_not_clear"},
        ),
    }

    if action not in endpoints:
        abort(400)

    method, path, payload = endpoints[action]

    try:
        render_request(method, path, payload)
        flash(f"{action.title()} অনুরোধ Render-এ পাঠানো হয়েছে।", "success")
    except Exception as exc:
        flash(f"কাজটি সম্পন্ন হয়নি: {exc}", "error")

    return redirect(url_for("dashboard"))


@app.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id):
    with db() as con:
        con.execute(
            "DELETE FROM projects WHERE id = ?",
            (project_id,),
        )

    # This removes only the dashboard record.
    # It does NOT delete the actual Render service.
    flash("Dashboard থেকে Project record মুছে ফেলা হয়েছে।", "success")
    return redirect(url_for("dashboard"))


@app.route("/health")
def health():
    return {"status": "ok", "app": "SHANTO BOT HOSTING V3"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")))

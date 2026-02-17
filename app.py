from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)
DB_PATH = BASE_DIR / "data.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "task-to-reward-dev-secret")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_: Any) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def now_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def init_db() -> None:
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            contact TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_blocked INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            reward REAL NOT NULL,
            instructions TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            screenshot_path TEXT NOT NULL,
            screenshot_hash TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            rejection_reason TEXT,
            submitted_at TEXT NOT NULL,
            decided_at TEXT,
            decided_by_admin_id INTEGER,
            UNIQUE(user_id, task_id),
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(task_id) REFERENCES tasks(id)
        );

        CREATE TABLE IF NOT EXISTS wallet_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            txn_type TEXT NOT NULL,
            description TEXT NOT NULL,
            reference_type TEXT,
            reference_id INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS withdrawals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            upi_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            payment_proof_path TEXT,
            rejection_reason TEXT,
            requested_at TEXT NOT NULL,
            decided_at TEXT,
            decided_by_admin_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS feature_flags (
            key TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS admin_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT NOT NULL
        );
        """
    )

    admin = db.execute("SELECT * FROM admins WHERE username = ?", (DEFAULT_ADMIN_USERNAME,)).fetchone()
    if not admin:
        db.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (DEFAULT_ADMIN_USERNAME, hash_text(DEFAULT_ADMIN_PASSWORD), now_str()),
        )

    if not db.execute("SELECT 1 FROM settings WHERE key='minimum_withdrawal'").fetchone():
        db.execute("INSERT INTO settings (key, value) VALUES ('minimum_withdrawal', '300')")

    default_flags = [
        "sponsored_tasks",
        "banner_ads",
        "video_ads",
        "referral_system",
        "telegram_notifications",
        "vip_users",
        "analytics_dashboard",
        "multiple_withdrawal_methods",
    ]
    for flag in default_flags:
        if not db.execute("SELECT 1 FROM feature_flags WHERE key=?", (flag,)).fetchone():
            db.execute("INSERT INTO feature_flags (key, enabled) VALUES (?, 0)", (flag,))

    db.commit()


def user_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            flash("Admin login required.", "warning")
            return redirect(url_for("admin_login"))
        return view(*args, **kwargs)

    return wrapped


def get_wallet_balance(user_id: int) -> float:
    db = get_db()
    row = db.execute("SELECT COALESCE(SUM(amount), 0) as bal FROM wallet_transactions WHERE user_id=?", (user_id,)).fetchone()
    return float(row["bal"])


def get_total_earnings(user_id: int) -> float:
    row = get_db().execute(
        "SELECT COALESCE(SUM(amount), 0) as total FROM wallet_transactions WHERE user_id=? AND txn_type='credit'",
        (user_id,),
    ).fetchone()
    return float(row["total"])


def get_total_withdrawn(user_id: int) -> float:
    row = get_db().execute(
        "SELECT COALESCE(SUM(ABS(amount)), 0) as total FROM wallet_transactions WHERE user_id=? AND txn_type='debit'",
        (user_id,),
    ).fetchone()
    return float(row["total"])


def log_admin_action(admin_id: int, action: str, details: str = "") -> None:
    db = get_db()
    db.execute(
        "INSERT INTO admin_actions (admin_id, action, details, created_at) VALUES (?, ?, ?, ?)",
        (admin_id, action, details, now_str()),
    )
    db.commit()


@app.before_request
def setup() -> None:
    init_db()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        contact = request.form.get("contact", "").strip().lower()
        password = request.form.get("password", "")

        if not all([name, contact, password]):
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (name, contact, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, contact, hash_text(password), now_str()),
            )
            db.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Account already exists with this mobile/email.", "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        contact = request.form.get("contact", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE contact=? AND password_hash=?",
            (contact, hash_text(password)),
        ).fetchone()

        if not user:
            flash("Invalid credentials.", "danger")
        elif user["is_blocked"]:
            flash("Account is blocked. Contact support.", "danger")
        else:
            session.clear()
            session["user_id"] = user["id"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("user_dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("home"))


@app.route("/dashboard")
@user_required
def user_dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    return render_template(
        "user_dashboard.html",
        user=user,
        balance=get_wallet_balance(user["id"]),
        total_earnings=get_total_earnings(user["id"]),
        total_withdrawn=get_total_withdrawn(user["id"]),
    )


@app.route("/tasks", methods=["GET", "POST"])
@user_required
def tasks_page():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if request.method == "POST":
        if user["is_blocked"]:
            flash("Blocked users cannot submit tasks.", "danger")
            return redirect(url_for("tasks_page"))

        task_id = int(request.form.get("task_id", 0))
        file = request.files.get("screenshot")
        if not file or not file.filename:
            flash("Screenshot required.", "danger")
            return redirect(url_for("tasks_page"))

        content = file.read()
        if not content:
            flash("Invalid file.", "danger")
            return redirect(url_for("tasks_page"))

        shot_hash = hashlib.sha256(content).hexdigest()
        existing_hash = db.execute("SELECT id FROM submissions WHERE screenshot_hash=?", (shot_hash,)).fetchone()
        if existing_hash:
            flash("Duplicate screenshot detected.", "danger")
            return redirect(url_for("tasks_page"))

        existing_submission = db.execute(
            "SELECT id FROM submissions WHERE user_id=? AND task_id=?",
            (session["user_id"], task_id),
        ).fetchone()
        if existing_submission:
            flash("You already submitted this task.", "warning")
            return redirect(url_for("tasks_page"))

        filename = f"sub_{session['user_id']}_{task_id}_{int(datetime.utcnow().timestamp())}_{secure_filename(file.filename)}"
        save_path = UPLOAD_DIR / filename
        with open(save_path, "wb") as fp:
            fp.write(content)

        db.execute(
            """
            INSERT INTO submissions (user_id, task_id, screenshot_path, screenshot_hash, submitted_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session["user_id"], task_id, filename, shot_hash, now_str()),
        )
        db.commit()
        flash("Task submitted successfully for manual review.", "success")
        return redirect(url_for("tasks_page"))

    tasks = db.execute("SELECT * FROM tasks WHERE is_active=1 ORDER BY id DESC").fetchall()
    user_subs = {
        row["task_id"]: row
        for row in db.execute("SELECT * FROM submissions WHERE user_id=?", (session["user_id"],)).fetchall()
    }
    return render_template("tasks.html", tasks=tasks, user_subs=user_subs, user=user)


@app.route("/task-history")
@user_required
def task_history():
    rows = get_db().execute(
        """
        SELECT s.*, t.name as task_name, t.reward
        FROM submissions s
        JOIN tasks t ON t.id = s.task_id
        WHERE s.user_id=? ORDER BY s.id DESC
        """,
        (session["user_id"],),
    ).fetchall()
    return render_template("task_history.html", rows=rows)


@app.route("/withdrawal", methods=["GET", "POST"])
@user_required
def withdrawal_page():
    db = get_db()
    user_id = session["user_id"]
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    min_withdraw = float(db.execute("SELECT value FROM settings WHERE key='minimum_withdrawal'").fetchone()["value"])
    balance = get_wallet_balance(user_id)

    if request.method == "POST":
        if user["is_blocked"]:
            flash("Blocked users cannot request withdrawal.", "danger")
            return redirect(url_for("withdrawal_page"))

        pending = db.execute(
            "SELECT id FROM withdrawals WHERE user_id=? AND status='Pending'",
            (user_id,),
        ).fetchone()
        if pending:
            flash("You already have one pending withdrawal.", "warning")
            return redirect(url_for("withdrawal_page"))

        amount = float(request.form.get("amount", "0") or 0)
        upi = request.form.get("upi_id", "").strip()

        if not upi or amount <= 0:
            flash("Valid amount and UPI ID required.", "danger")
            return redirect(url_for("withdrawal_page"))

        if amount < min_withdraw:
            flash(f"Minimum withdrawal is ₹{min_withdraw:.0f}", "danger")
            return redirect(url_for("withdrawal_page"))

        if amount > balance:
            flash("Insufficient balance.", "danger")
            return redirect(url_for("withdrawal_page"))

        db.execute(
            "INSERT INTO withdrawals (user_id, amount, upi_id, requested_at) VALUES (?, ?, ?, ?)",
            (user_id, amount, upi, now_str()),
        )
        db.commit()
        flash("Withdrawal request placed. Manual processing within 24-72 hours.", "success")
        return redirect(url_for("withdrawal_page"))

    rows = db.execute("SELECT * FROM withdrawals WHERE user_id=? ORDER BY id DESC", (user_id,)).fetchall()
    return render_template("withdrawal.html", balance=balance, min_withdraw=min_withdraw, rows=rows)


@app.route("/wallet")
@user_required
def wallet_history():
    rows = get_db().execute(
        "SELECT * FROM wallet_transactions WHERE user_id=? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("wallet.html", rows=rows, balance=get_wallet_balance(session["user_id"]))


@app.route("/uploads/<path:filename>")
def uploads(filename: str):
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/about-terms")
def about_terms():
    return render_template("about_terms.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        admin = get_db().execute(
            "SELECT * FROM admins WHERE username=? AND password_hash=?",
            (username, hash_text(password)),
        ).fetchone()
        if admin:
            session.clear()
            session["admin_id"] = admin["id"]
            flash("Admin login successful.", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid admin credentials.", "danger")
    return render_template("admin_login.html", username_hint=DEFAULT_ADMIN_USERNAME, password_hint=DEFAULT_ADMIN_PASSWORD)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    db = get_db()
    stats = {
        "total_users": db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "total_earnings": db.execute(
            "SELECT COALESCE(SUM(amount),0) c FROM wallet_transactions WHERE txn_type='credit'"
        ).fetchone()["c"],
        "total_withdrawals": db.execute(
            "SELECT COALESCE(SUM(amount),0) c FROM withdrawals WHERE status='Paid'"
        ).fetchone()["c"],
        "pending_tasks": db.execute("SELECT COUNT(*) c FROM submissions WHERE status='Pending'").fetchone()["c"],
        "pending_withdrawals": db.execute("SELECT COUNT(*) c FROM withdrawals WHERE status='Pending'").fetchone()["c"],
    }
    return render_template("admin_dashboard.html", stats=stats)


@app.route("/admin/tasks", methods=["GET", "POST"])
@admin_required
def admin_tasks():
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            name = request.form.get("name", "").strip()
            reward = float(request.form.get("reward", "0") or 0)
            instructions = request.form.get("instructions", "").strip()
            if name and reward > 0 and instructions:
                db.execute(
                    "INSERT INTO tasks (name, reward, instructions, is_active, created_at) VALUES (?, ?, ?, ?, ?)",
                    (name, reward, instructions, 1, now_str()),
                )
                db.commit()
                log_admin_action(session["admin_id"], "add_task", name)
                flash("Task added.", "success")
        elif action == "toggle":
            task_id = int(request.form.get("task_id", "0"))
            db.execute("UPDATE tasks SET is_active = 1 - is_active WHERE id=?", (task_id,))
            db.commit()
            log_admin_action(session["admin_id"], "toggle_task", str(task_id))
        elif action == "delete":
            task_id = int(request.form.get("task_id", "0"))
            db.execute("DELETE FROM tasks WHERE id=?", (task_id,))
            db.commit()
            log_admin_action(session["admin_id"], "delete_task", str(task_id))
        elif action == "edit":
            task_id = int(request.form.get("task_id", "0"))
            name = request.form.get("name", "").strip()
            reward = float(request.form.get("reward", "0") or 0)
            instructions = request.form.get("instructions", "").strip()
            db.execute(
                "UPDATE tasks SET name=?, reward=?, instructions=? WHERE id=?",
                (name, reward, instructions, task_id),
            )
            db.commit()
            log_admin_action(session["admin_id"], "edit_task", str(task_id))
        return redirect(url_for("admin_tasks"))

    tasks = db.execute("SELECT * FROM tasks ORDER BY id DESC").fetchall()
    return render_template("admin_tasks.html", tasks=tasks)


@app.route("/admin/submissions", methods=["GET", "POST"])
@admin_required
def admin_submissions():
    db = get_db()
    if request.method == "POST":
        sub_id = int(request.form.get("submission_id", "0"))
        decision = request.form.get("decision")
        reason = request.form.get("reason", "").strip()
        sub = db.execute(
            "SELECT s.*, t.reward, t.name as task_name FROM submissions s JOIN tasks t ON t.id=s.task_id WHERE s.id=?",
            (sub_id,),
        ).fetchone()
        if sub and sub["status"] == "Pending":
            if decision == "approve":
                db.execute(
                    "UPDATE submissions SET status='Approved', decided_at=?, decided_by_admin_id=? WHERE id=?",
                    (now_str(), session["admin_id"], sub_id),
                )
                db.execute(
                    """
                    INSERT INTO wallet_transactions (user_id, amount, txn_type, description, reference_type, reference_id, created_at)
                    VALUES (?, ?, 'credit', ?, 'submission', ?, ?)
                    """,
                    (sub["user_id"], sub["reward"], f"Reward for {sub['task_name']}", sub_id, now_str()),
                )
                db.commit()
                log_admin_action(session["admin_id"], "approve_submission", str(sub_id))
            else:
                db.execute(
                    "UPDATE submissions SET status='Rejected', rejection_reason=?, decided_at=?, decided_by_admin_id=? WHERE id=?",
                    (reason or "Policy mismatch", now_str(), session["admin_id"], sub_id),
                )
                db.commit()
                log_admin_action(session["admin_id"], "reject_submission", str(sub_id))
        return redirect(url_for("admin_submissions"))

    rows = db.execute(
        """
        SELECT s.*, u.name as user_name, u.contact, t.name as task_name, t.reward
        FROM submissions s
        JOIN users u ON u.id=s.user_id
        JOIN tasks t ON t.id=s.task_id
        ORDER BY s.id DESC
        """
    ).fetchall()
    return render_template("admin_submissions.html", rows=rows)


@app.route("/admin/withdrawals", methods=["GET", "POST"])
@admin_required
def admin_withdrawals():
    db = get_db()
    if request.method == "POST":
        wid = int(request.form.get("withdrawal_id", "0"))
        decision = request.form.get("decision")
        reason = request.form.get("reason", "").strip()
        wd = db.execute("SELECT * FROM withdrawals WHERE id=?", (wid,)).fetchone()

        if wd and wd["status"] == "Pending":
            if decision == "paid":
                proof = request.files.get("payment_proof")
                proof_name = None
                if proof and proof.filename:
                    proof_name = f"pay_{wid}_{int(datetime.utcnow().timestamp())}_{secure_filename(proof.filename)}"
                    proof.save(UPLOAD_DIR / proof_name)

                balance = get_wallet_balance(wd["user_id"])
                if balance >= wd["amount"]:
                    db.execute(
                        "UPDATE withdrawals SET status='Paid', payment_proof_path=?, decided_at=?, decided_by_admin_id=? WHERE id=?",
                        (proof_name, now_str(), session["admin_id"], wid),
                    )
                    db.execute(
                        """
                        INSERT INTO wallet_transactions (user_id, amount, txn_type, description, reference_type, reference_id, created_at)
                        VALUES (?, ?, 'debit', ?, 'withdrawal', ?, ?)
                        """,
                        (wd["user_id"], -wd["amount"], f"Withdrawal paid to {wd['upi_id']}", wid, now_str()),
                    )
                    db.commit()
                    log_admin_action(session["admin_id"], "paid_withdrawal", str(wid))
            elif decision == "reject":
                db.execute(
                    "UPDATE withdrawals SET status='Rejected', rejection_reason=?, decided_at=?, decided_by_admin_id=? WHERE id=?",
                    (reason or "Rejected by admin", now_str(), session["admin_id"], wid),
                )
                db.commit()
                log_admin_action(session["admin_id"], "reject_withdrawal", str(wid))
        return redirect(url_for("admin_withdrawals"))

    rows = db.execute(
        "SELECT w.*, u.name as user_name, u.contact FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC"
    ).fetchall()
    return render_template("admin_withdrawals.html", rows=rows)


@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    db = get_db()
    if request.method == "POST":
        user_id = int(request.form.get("user_id", "0"))
        db.execute("UPDATE users SET is_blocked = 1 - is_blocked WHERE id=?", (user_id,))
        db.commit()
        log_admin_action(session["admin_id"], "toggle_user_block", str(user_id))
        return redirect(url_for("admin_users"))

    rows = db.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    return render_template("admin_users.html", rows=rows)


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    db = get_db()
    if request.method == "POST":
        min_withdraw = request.form.get("minimum_withdrawal")
        if min_withdraw:
            db.execute("UPDATE settings SET value=? WHERE key='minimum_withdrawal'", (min_withdraw,))
        for flag in db.execute("SELECT key FROM feature_flags").fetchall():
            enabled = 1 if request.form.get(f"flag_{flag['key']}") else 0
            db.execute("UPDATE feature_flags SET enabled=? WHERE key=?", (enabled, flag["key"]))
        db.commit()
        log_admin_action(session["admin_id"], "update_settings", "minimum_withdrawal/features")
        flash("Settings updated.", "success")
        return redirect(url_for("admin_settings"))

    min_withdraw = db.execute("SELECT value FROM settings WHERE key='minimum_withdrawal'").fetchone()["value"]
    flags = db.execute("SELECT * FROM feature_flags ORDER BY key").fetchall()
    return render_template("admin_settings.html", min_withdraw=min_withdraw, flags=flags)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

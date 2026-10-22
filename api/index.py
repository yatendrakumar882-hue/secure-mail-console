
import os
import re
import ssl
import json
import secrets
import smtplib
import urllib.parse
import urllib.request
from pathlib import Path
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session
)

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

# Configure these in Vercel Environment Variables.
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

# Fallback prevents import-time failure; set SESSION_SECRET in production.
app.secret_key = SESSION_SECRET or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20
MAX_RECIPIENTS = 25

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def logged_in():
    return session.get("authenticated") is True


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not logged_in():
            if request.path.startswith("/api/") or request.path == "/send-batch":
                return jsonify({"success": False, "message": "Please log in again."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def valid_email(value):
    return (
        isinstance(value, str)
        and len(value.strip()) <= 254
        and bool(EMAIL_RE.fullmatch(value.strip()))
    )


def clean_header(value, limit=250):
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY or not token:
        return False

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    data = urllib.parse.urlencode(payload).encode()
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))
        return result.get("success") is True
    except Exception:
        return False


def plain_text(html):
    text = re.sub(r"(?i)<br\s*/?>", "\n", html)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"<[^>]*>", "", text)
    for old, new in {
        "&nbsp;": " ", "&amp;": "&", "&lt;": "<",
        "&gt;": ">", "&quot;": '"', "&#39;": "'",
    }.items():
        text = text.replace(old, new)
    return text.strip()


def send_one(gmail, app_password, sender_name, recipient, subject, body, is_html):
    message = MIMEMultipart("alternative")
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    if is_html:
        message.attach(MIMEText(plain_text(body), "plain", "utf-8"))
        message.attach(MIMEText(body, "html", "utf-8"))
    else:
        message.attach(MIMEText(body, "plain", "utf-8"))

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(
        SMTP_HOST, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT
    ) as server:
        server.login(gmail, re.sub(r"\s+", "", app_password))
        refused = server.sendmail(gmail, [recipient], message.as_string())
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)


@app.route("/sw.js")
def service_worker():
    response = app.response_class("", mimetype="application/javascript")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))

    error = None
    if request.method == "POST":
        if not SESSION_SECRET or not LOGIN_PASSWORD:
            error = "Login configuration is missing. Check Vercel Environment Variables."
        else:
            password = request.form.get("password", "")
            if secrets.compare_digest(password, LOGIN_PASSWORD):
                session.clear()
                session.permanent = True
                session["authenticated"] = True
                return redirect(url_for("home"))
            error = "Incorrect password."

    return render_template(
        "login.html",
        error=error,
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def home():
    return render_template("index.html", turnstile_site_key=TURNSTILE_SITE_KEY)


@app.route("/send-batch", methods=["POST"])
@login_required
def send_batch():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "Invalid request body."}), 400

    gmail = str(data.get("gmail", "")).strip().lower()
    app_password = str(data.get("app_password", "")).strip()
    sender_name = clean_header(data.get("sender_name", ""))
    subject = clean_header(data.get("subject", ""), 998)
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    recipients = data.get("recipients", [])
    token = str(data.get("turnstile_token", "")).strip()

    if not SESSION_SECRET or not LOGIN_PASSWORD:
        return jsonify({"success": False, "message": "Server login configuration is missing."}), 503
    if not TURNSTILE_SECRET_KEY:
        return jsonify({"success": False, "message": "Turnstile Secret Key is not configured."}), 503
    if not valid_email(gmail) or not gmail.endswith("@gmail.com"):
        return jsonify({"success": False, "message": "Enter a valid @gmail.com address."}), 400
    if not app_password or not sender_name or not subject or not body.strip():
        return jsonify({"success": False, "message": "Complete all message fields."}), 400
    if len(body) > 50000:
        return jsonify({"success": False, "message": "Message is too long."}), 400
    if data.get("consent_confirmed") is not True:
        return jsonify({"success": False, "message": "Confirm that recipients consented to receive this email."}), 400
    if not isinstance(recipients, list):
        return jsonify({"success": False, "message": "Recipients must be a list."}), 400
    if not verify_turnstile(token, request.remote_addr):
        return jsonify({"success": False, "message": "Cloudflare verification failed. Please retry."}), 403

    clean_recipients = []
    seen = set()
    for item in recipients:
        address = str(item.get("email", "") if isinstance(item, dict) else item).strip().lower()
        if valid_email(address) and address not in seen:
            clean_recipients.append(address)
            seen.add(address)

    clean_recipients = clean_recipients[:MAX_RECIPIENTS]
    if not clean_recipients:
        return jsonify({"success": False, "message": "No valid recipients found."}), 400

    sent, failed, errors = 0, 0, []
    for recipient in clean_recipients:
        try:
            send_one(
                gmail, app_password, sender_name, recipient,
                subject, body, is_html
            )
            sent += 1
        except Exception as exc:
            failed += 1
            # Do not expose credentials or full SMTP responses to the browser.
            errors.append({
                "email": recipient,
                "error": type(exc).__name__,
            })

    return jsonify({
        "success": failed == 0,
        "message": "Processing finished. SMTP acceptance does not guarantee Inbox placement.",
        "total": len(clean_recipients),
        "sent": sent,
        "failed": failed,
        "errors": errors,
    })


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# Vercel Python entry point
handler = app


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

SESSION_SECRET = os.environ.get("SESSION_SECRET", "")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

app.secret_key = SESSION_SECRET or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 15
MAX_RECIPIENTS = 25

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    return (
        isinstance(value, str)
        and len(value.strip()) <= 254
        and bool(EMAIL_RE.fullmatch(value.strip()))
    )


def clean_header(value, limit=250):
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("authenticated") is not True:
            if request.path.startswith("/api/") or request.path == "/send-batch":
                return jsonify({
                    "success": False,
                    "ok": False,
                    "message": "Your session expired. Please log in again."
                }), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def verify_turnstile(token):
    if not TURNSTILE_SECRET_KEY or not token:
        return False, "Turnstile keys or verification token are missing."

    payload = urllib.parse.urlencode({
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success") is True:
            return True, ""

        return False, "Cloudflare verification failed. Refresh the page and retry."

    except Exception:
        return False, "Could not contact the verification service. Please retry."


def html_to_text(html):
    text = re.sub(r"(?i)<br\s*/?>", "\n", html)
    text = re.sub(r"(?i)</(?:p|div|li|h[1-6])\s*>", "\n", text)
    text = re.sub(r"<[^>]*>", "", text)

    for old, new in {
        "&nbsp;": " ",
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
    }.items():
        text = text.replace(old, new)

    return text.strip()


def create_message(sender_name, gmail, recipient, subject, body, is_html):
    message = MIMEMultipart("alternative")
    message["From"] = formataddr((sender_name, gmail))
    message["To"] = recipient
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    if is_html:
        message.attach(MIMEText(html_to_text(body), "plain", "utf-8"))
        message.attach(MIMEText(body, "html", "utf-8"))
    else:
        message.attach(MIMEText(body, "plain", "utf-8"))

    return message


def smtp_error_message(exc):
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return (
            "Gmail authentication failed. Check the Gmail address, "
            "2-Step Verification and the 16-character Google App Password."
        )

    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "Gmail rejected the recipient address. Check that address."

    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "Gmail rejected the sender address."

    if isinstance(exc, smtplib.SMTPConnectError):
        return "Could not establish the Gmail SMTP connection."

    if isinstance(exc, (TimeoutError, OSError)):
        return "SMTP connection timed out or failed. Retry with fewer recipients."

    if isinstance(exc, smtplib.SMTPResponseException):
        return (
            f"Gmail SMTP returned error code {exc.smtp_code}. "
            "Check the Gmail account status and SMTP configuration."
        )

    if isinstance(exc, smtplib.SMTPException):
        return "Gmail SMTP rejected the message. Check the account and message."

    return f"Email sending failed ({type(exc).__name__})."


@app.route("/sw.js")
def service_worker():
    return app.response_class(
        "",
        mimetype="application/javascript",
        headers={"Cache-Control": "no-store"},
    )


@app.route("/favicon.ico")
def favicon():
    return "", 204


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated") is True:
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        if not SESSION_SECRET or not LOGIN_PASSWORD:
            error = "LOGIN_PASSWORD or SESSION_SECRET is missing in Vercel."
        else:
            supplied = request.form.get("password", "")

            if secrets.compare_digest(supplied, LOGIN_PASSWORD):
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
    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/send-batch", methods=["POST"])
@login_required
def send_batch():
    if not SESSION_SECRET or not LOGIN_PASSWORD:
        return jsonify({
            "success": False,
            "ok": False,
            "message": "Login environment variables are missing."
        }), 503

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "ok": False,
            "message": "Invalid request. Please refresh the page."
        }), 400

    gmail = str(data.get("gmail", "")).strip().lower()
    app_password = re.sub(r"\s+", "", str(data.get("app_password", "")))
    sender_name = clean_header(data.get("sender_name", ""))
    subject = clean_header(data.get("subject", ""), 200)
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    token = str(data.get("turnstile_token", "")).strip()
    recipients = data.get("recipients", [])

    if not gmail.endswith("@gmail.com") or not valid_email(gmail):
        return jsonify({
            "success": False,
            "ok": False,
            "message": "Enter a valid @gmail.com sender address."
        }), 400

    if not app_password:
        return jsonify({
            "success": False,
            "ok": False,
            "message": "Enter your Google App Password."
        }), 400

    if not sender_name or not subject or not body.strip():
        return jsonify({
            "success": False,
            "ok": False,
            "message": "Complete the sender name, subject and message."
        }), 400

    if len(body) > 40000:
        return jsonify({
            "success": False,
            "ok": False,
            "message": "The message is too long."
        }), 400

    if data.get("consent_confirmed") is not True:
        return jsonify({
            "success": False,
            "ok": False,
            "message": "Confirm that recipients agreed to receive your email."
        }), 400

    if not isinstance(recipients, list):
        return jsonify({
            "success": False,
            "ok": False,
            "message": "Recipient list is invalid."
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "ok": False,
            "message": f"Send at most {MAX_RECIPIENTS} recipients per request."
        }), 400

    verified, verification_message = verify_turnstile(token)

    if not verified:
        return jsonify({
            "success": False,
            "ok": False,
            "message": verification_message
        }), 403

    clean_recipients = []
    seen = set()

    for item in recipients:
        address = str(item).strip().lower()

        if valid_email(address) and address not in seen:
            clean_recipients.append(address)
            seen.add(address)

    if not clean_recipients:
        return jsonify({
            "success": False,
            "ok": False,
            "message": "No valid recipient addresses were found."
        }), 400

    sent = 0
    failed = 0
    errors = []

    try:
        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=SMTP_TIMEOUT,
            context=context,
        ) as server:
            server.login(gmail, app_password)

            for recipient in clean_recipients:
                try:
                    message = create_message(
                        sender_name,
                        gmail,
                        recipient,
                        subject,
                        body,
                        is_html,
                    )

                    refused = server.sendmail(
                        gmail,
                        [recipient],
                        message.as_string(),
                    )

                    if refused:
                        failed += 1
                        errors.append({
                            "email": recipient,
                            "error": "Recipient refused by SMTP",
                        })
                    else:
                        sent += 1

                except Exception as exc:
                    failed += 1
                    errors.append({
                        "email": recipient,
                        "error": smtp_error_message(exc),
                    })

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "success": False,
            "ok": False,
            "message": (
                "Gmail login failed. Use a valid Gmail address and "
                "Google App Password; a normal Gmail password will not work."
            ),
            "sent": 0,
            "failed": len(clean_recipients),
            "total": len(clean_recipients),
        }), 400

    except Exception as exc:
        return jsonify({
            "success": False,
            "ok": False,
            "message": smtp_error_message(exc),
            "sent": sent,
            "failed": failed + len(clean_recipients) - sent - failed,
            "total": len(clean_recipients),
        }), 502

    return jsonify({
        "success": failed == 0,
        "ok": failed == 0,
        "message": (
            "All messages were accepted by Gmail SMTP."
            if failed == 0
            else "Some messages failed. Review the errors below."
        ),
        "total": len(clean_recipients),
        "sent": sent,
        "failed": failed,
        "remaining": 0,
        "errors": errors,
    }), 200


handler = app


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
    redirect, url_for, session, Response, stream_with_context
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
                    "message": "Session expired. Please log in again."
                }), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def verify_turnstile(token):
    if not TURNSTILE_SECRET_KEY or not token:
        return False

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
        return result.get("success") is True
    except Exception:
        return False


def html_to_text(html):
    text = re.sub(r"(?i)<br\s*/?>", "\n", html)
    text = re.sub(r"(?i)</(?:p|div|li|h[1-6])\s*>", "\n", text)
    text = re.sub(r"<[^>]*>", "", text)

    for old, new in {
        "&nbsp;": " ", "&amp;": "&", "&lt;": "<",
        "&gt;": ">", "&quot;": '"', "&#39;": "'",
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
        return "Gmail login failed. Check the Gmail address and Google App Password."
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "Gmail rejected a recipient address."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "Gmail rejected the sender address."
    if isinstance(exc, (TimeoutError, OSError)):
        return "SMTP connection timed out or failed. Check connectivity and retry."
    if isinstance(exc, smtplib.SMTPResponseException):
        return f"Gmail SMTP returned error code {exc.smtp_code}."
    if isinstance(exc, smtplib.SMTPException):
        return "Gmail SMTP rejected the operation."
    return f"Sending failed ({type(exc).__name__})."


def json_line(event):
    return json.dumps(event, ensure_ascii=False) + "\n"


@app.route("/sw.js")
def service_worker():
    return Response(
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
            error = "Set LOGIN_PASSWORD and SESSION_SECRET in Vercel."
        elif secrets.compare_digest(
            request.form.get("password", ""),
            LOGIN_PASSWORD
        ):
            session.clear()
            session.permanent = True
            session["authenticated"] = True
            return redirect(url_for("home"))
        else:
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
            "message": "Server login configuration is missing."
        }), 503

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "message": "Invalid JSON request."
        }), 400

    gmail = str(data.get("gmail", "")).strip().lower()
    app_password = re.sub(r"\s+", "", str(data.get("app_password", "")))
    sender_name = clean_header(data.get("sender_name", ""))
    subject = clean_header(data.get("subject", ""), 200)
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    token = str(data.get("turnstile_token", "")).strip()
    recipients = data.get("recipients", [])

    if not valid_email(gmail) or not gmail.endswith("@gmail.com"):
        return jsonify({
            "success": False,
            "message": "Enter a valid @gmail.com sender address."
        }), 400

    if not app_password or not sender_name or not subject or not body.strip():
        return jsonify({
            "success": False,
            "message": "Complete all sender and message fields."
        }), 400

    if len(body) > 40000:
        return jsonify({
            "success": False,
            "message": "Message is too long."
        }), 400

    if data.get("consent_confirmed") is not True:
        return jsonify({
            "success": False,
            "message": "Confirm recipient consent before sending."
        }), 400

    if not isinstance(recipients, list) or len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "message": f"Provide no more than {MAX_RECIPIENTS} recipients."
        }), 400

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
            "message": "No valid recipient addresses found."
        }), 400

    if not TURNSTILE_SECRET_KEY:
        return jsonify({
            "success": False,
            "message": "Turnstile Secret Key is not configured."
        }), 503

    if not verify_turnstile(token):
        return jsonify({
            "success": False,
            "message": "Cloudflare verification failed. Please retry."
        }), 403

    total = len(clean_recipients)

    @stream_with_context
    def generate():
        sent = 0
        failed = 0

        yield json_line({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
            "message": "Starting SMTP connection..."
        })

        try:
            context = ssl.create_default_context()

            with smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT,
                context=context,
            ) as server:
                server.login(gmail, app_password)

                yield json_line({
                    "type": "progress",
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": total,
                    "message": "Gmail SMTP connected."
                })

                for recipient in clean_recipients:
                    try:
                        message = create_message(
                            sender_name, gmail, recipient,
                            subject, body, is_html
                        )

                        refused = server.sendmail(
                            gmail,
                            [recipient],
                            message.as_string(),
                        )

                        if refused:
                            failed += 1
                            error = "Recipient refused by SMTP."
                        else:
                            sent += 1
                            error = None

                    except Exception as exc:
                        failed += 1
                        error = smtp_error_message(exc)

                    event = {
                        "type": "progress",
                        "total": total,
                        "sent": sent,
                        "failed": failed,
                        "remaining": total - sent - failed,
                        "recipient": recipient,
                        "message": (
                            f"Processed {sent + failed} of {total}."
                        ),
                    }

                    if error:
                        event["error"] = error

                    yield json_line(event)

            yield json_line({
                "type": "complete",
                "success": failed == 0,
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining": 0,
                "message": (
                    "All messages accepted by Gmail SMTP."
                    if failed == 0
                    else "Finished with some sending failures."
                )
            })

        except Exception as exc:
            yield json_line({
                "type": "error",
                "success": False,
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining": total - sent - failed,
                "message": smtp_error_message(exc),
            })

    return Response(
        generate(),
        content_type="application/x-ndjson; charset=utf-8",
        headers={
            "Cache-Control": "no-cache, no-store, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


handler = app

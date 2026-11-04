# api/index.py

import os
import re
import ssl
import json
import time
import html
import secrets
import logging
import smtplib
import threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from email.utils import formataddr, make_msgid
from functools import wraps

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    jsonify,
    Response,
    stream_with_context,
)

# ------------------------------------------------------------
# App configuration
# ------------------------------------------------------------

app = Flask(__name__)

SESSION_SECRET = os.environ.get("SESSION_SECRET")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD")

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET environment variable is required.")

if not LOGIN_PASSWORD:
    raise RuntimeError("LOGIN_PASSWORD environment variable is required.")

app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 4
SEND_DELAY_SECONDS = 0.1

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Serialize pacing across worker threads.
_send_lock = threading.Lock()
_last_send_started = 0.0


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def valid_email(address):
    if not isinstance(address, str):
        return False

    address = address.strip()

    if len(address) > 254 or not EMAIL_RE.fullmatch(address):
        return False

    local, _, domain = address.rpartition("@")
    return bool(local and domain and len(local) <= 64)


def parse_recipients(raw_recipients):
    if isinstance(raw_recipients, list):
        candidates = raw_recipients
    elif isinstance(raw_recipients, str):
        candidates = re.split(r"[\s,;]+", raw_recipients)
    else:
        raise ValueError("Recipients must be a list or text.")

    recipients = []
    seen = set()

    for candidate in candidates:
        address = str(candidate).strip()
        if not address:
            continue

        normalized = address.lower()

        if not valid_email(address):
            raise ValueError(f"Invalid email address: {address}")

        if normalized not in seen:
            seen.add(normalized)
            recipients.append(address)

    if not recipients:
        raise ValueError("Please provide at least one recipient.")

    if len(recipients) > MAX_RECIPIENTS:
        raise ValueError(f"Maximum {MAX_RECIPIENTS} recipients are allowed.")

    return recipients


def html_to_plain_text(value):
    value = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", value)
    value = re.sub(r"(?i)</\s*(p|div|li|tr|h[1-6])\s*>", "\n", value)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html.unescape(value)
    value = re.sub(r"[ \t]+\n", "\n", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def recipient_name(address):
    local_part = address.split("@", 1)[0]
    cleaned = re.sub(r"[._+-]+", " ", local_part).strip()
    return cleaned.title() if cleaned else "there"


def personalize_template(template, recipient):
    name = recipient_name(recipient)

    replacements = {
        "{{hi}}": "Hi",
        "{{hello}}": "Hello",
        "{{thanks}}": "Thank you",
        "{{name}}": name,
        "{{email}}": recipient,
        "{{ref_code}}": secrets.token_hex(4).upper(),
    }

    result = template
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)

    return result


def pace_send_start():
    """Apply a small minimum interval between send attempts."""
    global _last_send_started

    with _send_lock:
        now = time.monotonic()
        wait_for = SEND_DELAY_SECONDS - (now - _last_send_started)

        if wait_for > 0:
            time.sleep(wait_for)

        _last_send_started = time.monotonic()


def build_message(
    sender_email,
    sender_name,
    recipient,
    subject,
    body,
    is_html,
):
    personalized_subject = personalize_template(subject, recipient)
    personalized_body = personalize_template(body, recipient)

    message = EmailMessage()
    message["Subject"] = personalized_subject
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = recipient
    message["Date"] = datetime.now(timezone.utc).strftime(
        "%a, %d %b %Y %H:%M:%S +0000"
    )
    message["Message-ID"] = make_msgid()

    if is_html:
        plain_body = html_to_plain_text(personalized_body) or " "
        message.set_content(plain_body)
        message.add_alternative(personalized_body, subtype="html")
    else:
        message.set_content(personalized_body)

    return message


def send_one_email(
    sender_email,
    app_password,
    sender_name,
    recipient,
    subject,
    body,
    is_html,
):
    try:
        message = build_message(
            sender_email=sender_email,
            sender_name=sender_name,
            recipient=recipient,
            subject=subject,
            body=body,
            is_html=is_html,
        )

        pace_send_start()

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=SMTP_TIMEOUT,
            context=context,
        ) as server:
            server.login(sender_email, app_password)
            server.send_message(
                message,
                from_addr=sender_email,
                to_addrs=[recipient],
            )

        return {
            "recipient": recipient,
            "success": True,
            "message": "Accepted by SMTP server",
        }

    except smtplib.SMTPAuthenticationError:
        return {
            "recipient": recipient,
            "success": False,
            "message": "SMTP authentication failed. Check Gmail and App Password.",
        }

    except smtplib.SMTPRecipientsRefused:
        return {
            "recipient": recipient,
            "success": False,
            "message": "Recipient was refused by the SMTP server.",
        }

    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        logger.warning("SMTP failure for recipient %s: %s", recipient, exc)
        return {
            "recipient": recipient,
            "success": False,
            "message": "SMTP connection or delivery error.",
        }

    except Exception:
        logger.exception("Unexpected send error for recipient %s", recipient)
        return {
            "recipient": recipient,
            "success": False,
            "message": "Unexpected sending error.",
        }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def json_stream_event(event):
    return json.dumps(event, ensure_ascii=False) + "\n"


# ------------------------------------------------------------
# Routes
# ------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("authenticated"):
            return redirect(url_for("index"))
        return render_template("login.html")

    password = request.form.get("password", "")

    if secrets.compare_digest(password, LOGIN_PASSWORD):
        session.clear()
        session["authenticated"] = True
        session.permanent = True
        return redirect(url_for("index))

    return render_template(
        "login.html",
        error="Incorrect password. Please try again.",
    ), 401


@app.route("/logout", methods=["POST", "GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})


@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return "", 204


@app.route("/send-batch", methods=["POST"])
@login_required
def send_batch():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid JSON request."}), 400

    sender_email = str(data.get("gmail", "")).strip()
    app_password = str(data.get("app_password", "")).strip()
    sender_name = str(data.get("sender_name", "")).strip()
    subject = str(data.get("subject", "")).strip()
    body = data.get("body", "")
    is_html = bool(data.get("is_html", False))
    consent_confirmed = bool(data.get("consent_confirmed", False))

    if not valid_email(sender_email):
        return jsonify({"ok": False, "error": "Enter a valid Gmail address."}), 400

    if not app_password:
        return jsonify({"ok": False, "error": "Gmail App Password is required."}), 400

    if not subject:
        return jsonify({"ok": False, "error": "Subject is required."}), 400

    if not isinstance(body, str) or not body.strip():
        return jsonify({"ok": False, "error": "Email body is required."}), 400

    if not consent_confirmed:
        return jsonify({
            "ok": False,
            "error": "Confirm that recipients have consented to receive these emails.",
        }), 400

    try:
        recipients = parse_recipients(data.get("recipients", ""))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    def generate():
        total = len(recipients)
        completed = 0
        successes = 0
        failures = 0

        yield json_stream_event({
            "type": "start",
            "total": total,
            "message": "Sending started.",
        })

        with ThreadPoolExecutor(max_workers=MAX_PARALLEL_SENDS) as executor:
            futures = {
                executor.submit(
                    send_one_email,
                    sender_email,
                    app_password,
                    sender_name,
                    recipient,
                    subject,
                    body,
                    is_html,
                ): recipient
                for recipient in recipients
            }

            for future in as_completed(futures):
                result = future.result()
                completed += 1

                if result["success"]:
                    successes += 1
                else:
                    failures += 1

                yield json_stream_event({
                    "type": "progress",
                    "completed": completed,
                    "total": total,
                    "success": successes,
                    "failed": failures,
                    "recipient": result["recipient"],
                    "ok": result["success"],
                    "message": result["message"],
                })

        yield json_stream_event({
            "type": "complete",
            "total": total,
            "success": successes,
            "failed": failures,
            "message": "Sending process finished.",
        })

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# Vercel Python entry point
handler = app

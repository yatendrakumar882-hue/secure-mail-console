# api/index.py

import os
import re
import ssl
import time
import secrets
import smtplib
import logging
import urllib.parse
import urllib.request

from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, session, redirect, url_for, render_template, Response, jsonify
from email.mime.text import MIMEText
from email.utils import format_datetime, make_msgid


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# ============================================================
# FLASK APP
# ============================================================

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

handler = app


# ============================================================
# ENVIRONMENT
# ============================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET")
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD")

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY")


if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET environment variable is required.")

if not LOGIN_PASSWORD:
    raise RuntimeError("LOGIN_PASSWORD environment variable is required.")


app.secret_key = SESSION_SECRET


# ============================================================
# SESSION SECURITY
# ============================================================

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# ============================================================
# LIMITS / SMTP
# ============================================================

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# Controlled pacing.
# This is rate control only; it does NOT bypass spam filtering.
SEND_DELAY_SECONDS = 2.0


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger(__name__)


# ============================================================
# EMAIL VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def is_valid_email(email):
    if not isinstance(email, str):
        return False

    email = email.strip()

    if len(email) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(email))


def normalize_email(email):
    return email.strip().lower()


def clean_header(value, max_length=998):
    """
    Prevent CRLF/header injection.
    """
    if value is None:
        return ""

    value = str(value)
    value = value.replace("\r", " ").replace("\n", " ")
    value = value.strip()

    return value[:max_length]


# ============================================================
# TURNSTILE
# ============================================================

def verify_turnstile(token, remote_ip=None):
    """
    Verify Cloudflare Turnstile token.

    If Turnstile keys are not configured, verification is skipped.
    """

    if not TURNSTILE_SECRET_KEY:
        return True

    if not token:
        return False

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode("utf-8")

        import json

        result = json.loads(data)

        return bool(result.get("success"))

    except Exception:
        logger.exception("Turnstile verification failed")
        return False


# ============================================================
# AUTH
# ============================================================

def is_authenticated():
    return session.get("authenticated") is True


@app.before_request
def require_login():
    public_paths = {
        "/login",
        "/health",
        "/static",
    }

    path = request.path

    if path == "/favicon.ico":
        return None

    if path == "/health":
        return None

    if path.startswith("/static/"):
        return None

    if path == "/login":
        return None

    if not is_authenticated():
        return redirect(url_for("login"))

    return None


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if is_authenticated():
        return redirect(url_for("index"))

    if request.method == "POST":

        password = request.form.get("password", "")

        if not secrets.compare_digest(
            str(password),
            str(LOGIN_PASSWORD),
        ):
            return render_template(
                "login.html",
                error="Invalid password.",
            ), 401

        session.clear()

        session["authenticated"] = True
        session.permanent = True

        return redirect(url_for("index"))

    return render_template("login.html")


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# EMAIL MESSAGE
# ============================================================

def build_message(
    sender,
    recipient,
    subject,
    body,
):
    """
    Build a normal RFC-compliant plain-text email.

    No forged headers.
    No fake Received headers.
    No Return-Path manipulation.
    No random/spintax content.
    """

    sender = clean_header(sender)
    recipient = clean_header(recipient)
    subject = clean_header(subject)

    body = str(body or "").replace("\x00", "")

    message = MIMEText(
        body,
        _subtype="plain",
        _charset="utf-8",
    )

    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message["Date"] = format_datetime(
        datetime.now(timezone.utc),
        usegmt=True,
    )
    message["Message-ID"] = make_msgid()
    message["MIME-Version"] = "1.0"

    return message


# ============================================================
# SEND ONE EMAIL
# ============================================================

def send_one_email(
    sender,
    app_password,
    recipient,
    subject,
    body,
):
    """
    Send one authenticated Gmail SMTP message.

    A fresh connection is intentionally used for each message.
    This keeps individual failures isolated and avoids sharing
    SMTP connection state between worker threads.
    """

    smtp = None

    try:
        message = build_message(
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
        )

        context = ssl.create_default_context()

        smtp = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=SMTP_TIMEOUT,
            context=context,
        )

        smtp.ehlo()

        smtp.login(
            sender,
            app_password,
        )

        smtp.sendmail(
            sender,
            [recipient],
            message.as_string(),
        )

        logger.info(
            "Email accepted by SMTP for recipient=%s",
            recipient,
        )

        return {
            "success": True,
            "recipient": recipient,
            "message": "Accepted by SMTP server.",
        }

    except smtplib.SMTPAuthenticationError:
        logger.warning(
            "SMTP authentication failed for sender=%s",
            sender,
        )

        return {
            "success": False,
            "recipient": recipient,
            "message": "SMTP authentication failed. Check Gmail address/App Password.",
        }

    except smtplib.SMTPRecipientsRefused:
        logger.warning(
            "Recipient refused: %s",
            recipient,
        )

        return {
            "success": False,
            "recipient": recipient,
            "message": "Recipient was refused by SMTP server.",
        }

    except smtplib.SMTPException as exc:
        logger.warning(
            "SMTP error for recipient=%s: %s",
            recipient,
            type(exc).__name__,
        )

        return {
            "success": False,
            "recipient": recipient,
            "message": "SMTP error while sending.",
        }

    except (OSError, TimeoutError):
        logger.warning(
            "Network/timeout error for recipient=%s",
            recipient,
        )

        return {
            "success": False,
            "recipient": recipient,
            "message": "Network or SMTP timeout.",
        }

    except Exception:
        logger.exception(
            "Unexpected send error for recipient=%s",
            recipient,
        )

        return {
            "success": False,
            "recipient": recipient,
            "message": "Unexpected error while sending.",
        }

    finally:
        if smtp is not None:

            try:
                smtp.quit()

            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass


# ============================================================
# SEND BATCH
# ============================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():

    # --------------------------------------------------------
    # Parse JSON
    # --------------------------------------------------------

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "success": False,
            "error": "Invalid JSON request.",
        }), 400


    # --------------------------------------------------------
    # Read input
    # --------------------------------------------------------

    gmail = clean_header(
        data.get("gmail", ""),
        max_length=254,
    )

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = clean_header(
        data.get("subject", ""),
        max_length=998,
    )

    body = str(
        data.get("body", "")
    )


    # --------------------------------------------------------
    # Basic validation
    # --------------------------------------------------------

    if not gmail:
        return jsonify({
            "success": False,
            "error": "Gmail address is required.",
        }), 400

    if not is_valid_email(gmail):
        return jsonify({
            "success": False,
            "error": "Invalid Gmail address.",
        }), 400

    if not app_password:
        return jsonify({
            "success": False,
            "error": "Google App Password is required.",
        }), 400

    if not subject:
        return jsonify({
            "success": False,
            "error": "Subject is required.",
        }), 400

    if not body.strip():
        return jsonify({
            "success": False,
            "error": "Email body is required.",
        }), 400

    if len(body) > 100_000:
        return jsonify({
            "success": False,
            "error": "Email body is too large.",
        }), 400


    # --------------------------------------------------------
    # Gmail sender validation
    # --------------------------------------------------------

    if not gmail.lower().endswith("@gmail.com"):
        return jsonify({
            "success": False,
            "error": "Please use a Gmail address with Gmail SMTP.",
        }), 400


    # --------------------------------------------------------
    # Recipients
    # --------------------------------------------------------

    raw_recipients = data.get("recipients")

    if not isinstance(raw_recipients, list):
        return jsonify({
            "success": False,
            "error": "Recipients must be an array.",
        }), 400


    recipients = []

    seen = set()

    for item in raw_recipients:

        if not isinstance(item, str):
            continue

        email = normalize_email(item)

        if not email:
            continue

        if not is_valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)
        recipients.append(email)


    if not recipients:
        return jsonify({
            "success": False,
            "error": "No valid recipients found.",
        }), 400


    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "success": False,
            "error": f"Maximum {MAX_RECIPIENTS} recipients are allowed per batch.",
        }), 400


    # --------------------------------------------------------
    # Turnstile
    # --------------------------------------------------------

    turnstile_token = data.get("turnstile_token", "")

    remote_ip = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr,
    )

    if remote_ip and "," in remote_ip:
        remote_ip = remote_ip.split(",", 1)[0].strip()


    if not verify_turnstile(
        turnstile_token,
        remote_ip,
    ):
        return jsonify({
            "success": False,
            "error": "Security verification failed.",
        }), 403


    # --------------------------------------------------------
    # Streaming response
    # --------------------------------------------------------

    def generate():

        total = len(recipients)
        completed = 0
        successful = 0
        failed = 0

        import json


        # Initial status event
        yield (
            json.dumps({
                "type": "start",
                "total": total,
            }) + "\n"
        )


        # ----------------------------------------------------
        # Two controlled workers
        # ----------------------------------------------------

        with ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        ) as executor:

            future_map = {}

            for recipient in recipients:

                future = executor.submit(
                    send_one_email,
                    gmail,
                    app_password,
                    recipient,
                    subject,
                    body,
                )

                future_map[future] = recipient


            # ------------------------------------------------
            # Process completed sends
            # ------------------------------------------------

            for future in as_completed(future_map):

                recipient = future_map[future]

                try:
                    result = future.result()

                except Exception:
                    result = {
                        "success": False,
                        "recipient": recipient,
                        "message": "Unexpected worker error.",
                    }


                completed += 1


                if result.get("success"):
                    successful += 1
                else:
                    failed += 1


                event = {
                    "type": "progress",
                    "completed": completed,
                    "total": total,
                    "successful": successful,
                    "failed": failed,
                    "recipient": recipient,
                    "success": bool(result.get("success")),
                    "message": result.get("message", ""),
                }


                yield (
                    json.dumps(event)
                    + "\n"
                )


                # --------------------------------------------
                # Controlled pacing
                #
                # This is NOT an inbox-bypass mechanism.
                # --------------------------------------------

                if completed < total:
                    time.sleep(SEND_DELAY_SECONDS)


        # ----------------------------------------------------
        # Finished
        # ----------------------------------------------------

        yield (
            json.dumps({
                "type": "complete",
                "total": total,
                "successful": successful,
                "failed": failed,
            }) + "\n"
        )


    response = Response(
        generate(),
        status=200,
        mimetype="application/x-ndjson",
    )


    # --------------------------------------------------------
    # Streaming / proxy headers
    # --------------------------------------------------------

    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate, "
        "no-transform, max-age=0"
    )

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return response


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "mail-sender",
    })


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    Response,
    stream_with_context,
)

import json
import os
import queue
import re
import secrets
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path


# ============================================================
# APP
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

handler = app


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

SESSION_SECRET = os.environ.get(
    "SESSION_SECRET",
    ""
).strip()

LOGIN_PASSWORD = os.environ.get(
    "LOGIN_PASSWORD",
    ""
).strip()

TURNSTILE_SITE_KEY = os.environ.get(
    "TURNSTILE_SITE_KEY",
    ""
).strip()

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    ""
).strip()


if not SESSION_SECRET:
    raise RuntimeError(
        "SESSION_SECRET is not configured in Vercel."
    )

if not LOGIN_PASSWORD:
    raise RuntimeError(
        "LOGIN_PASSWORD is not configured in Vercel."
    )

app.secret_key = SESSION_SECRET


# ============================================================
# SESSION
# ============================================================

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# ============================================================
# SMTP / SENDING SETTINGS
# ============================================================

MAX_RECIPIENTS = 25

MAX_PARALLEL_SENDS = 3

SEND_DELAY_SECONDS = 1.8

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20


# ============================================================
# INPUT LIMITS
# ============================================================

MAX_SENDER_NAME_LENGTH = 200
MAX_EMAIL_LENGTH = 254
MAX_SUBJECT_LENGTH = 998
MAX_BODY_LENGTH = 100_000


# ============================================================
# EMAIL VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    if not value:
        return False

    if len(value) > MAX_EMAIL_LENGTH:
        return False

    return bool(EMAIL_RE.fullmatch(value))


def normalize_email(value):
    return str(value or "").strip().lower()


def authenticated():
    return session.get("authenticated") is True


def clean_header(value, max_length=998):
    """
    Remove CR/LF from values used in mail headers.
    """

    value = str(value or "")

    value = value.replace("\r", " ")
    value = value.replace("\n", " ")

    value = value.strip()

    return value[:max_length]


def safe_error(exc, fallback):
    text = str(exc or "").strip()

    if not text:
        return fallback

    return text[:300]


# ============================================================
# LOGIN PROTECTION
# ============================================================

@app.before_request
def require_login():

    endpoint = request.endpoint

    if endpoint in {
        "login",
        "health",
        "static",
    }:
        return None

    if authenticated():
        return None

    if (
        request.path.startswith("/api/")
        or request.path == "/send-batch"
    ):
        return jsonify({
            "success": False,
            "message": "Authentication required.",
            "login_required": True,
        }), 401

    return redirect(url_for("login"))


# ============================================================
# TURNSTILE
# ============================================================

def verify_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET_KEY:
        return (
            False,
            "TURNSTILE_SECRET_KEY is not configured.",
        )

    if not token:
        return (
            False,
            "Cloudflare verification is required.",
        )

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        payload
    ).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type":
                "application/x-www-form-urlencoded",
        },
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=10,
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        return (
            False,
            "Cloudflare verification failed.",
        )

    except Exception:

        return (
            False,
            "Unable to verify Cloudflare.",
        )


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if authenticated():
        return redirect(url_for("home"))

    if request.method == "GET":

        return render_template(
            "login.html",
            error=None,
            turnstile_site_key=TURNSTILE_SITE_KEY,
        )

    password = str(
        request.form.get("password", "")
    )

    if not LOGIN_PASSWORD:

        return render_template(
            "login.html",
            error=(
                "LOGIN_PASSWORD is not configured "
                "in Vercel."
            ),
            turnstile_site_key=TURNSTILE_SITE_KEY,
        ), 500

    if not secrets.compare_digest(
        password,
        LOGIN_PASSWORD,
    ):

        return render_template(
            "login.html",
            error="Incorrect password.",
            turnstile_site_key=TURNSTILE_SITE_KEY,
        ), 401

    session.clear()

    session.permanent = True
    session["authenticated"] = True

    return redirect(url_for("home"))


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()

    return redirect(url_for("login"))


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    if not authenticated():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# ============================================================
# HTML -> PLAIN TEXT
# ============================================================

def html_to_plain_text(html):

    text = str(html or "")

    # Remove script/style blocks
    text = re.sub(
        r"<(script|style)\b[^>]*>.*?</\1>",
        "",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # Convert common line-break elements
    text = re.sub(
        r"<br\s*/?>",
        "\n",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"</(p|div|li|tr|h[1-6])\s*>",
        "\n",
        text,
        flags=re.IGNORECASE,
    )

    # Remove remaining HTML tags
    text = re.sub(
        r"<[^>]+>",
        "",
        text,
    )

    # Basic HTML entities
    replacements = {
        "&nbsp;": " ",
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    # Normalize spaces
    text = re.sub(
        r"[ \t]+",
        " ",
        text,
    )

    text = re.sub(
        r"\n\s*\n\s*\n+",
        "\n\n",
        text,
    )

    return text.strip()


# ============================================================
# BUILD EMAIL
# ============================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    final_subject = clean_header(
        subject,
        MAX_SUBJECT_LENGTH,
    )

    final_sender_name = clean_header(
        sender_name,
        MAX_SENDER_NAME_LENGTH,
    )

    final_recipient = clean_header(
        recipient,
        MAX_EMAIL_LENGTH,
    )

    final_body = str(
        body or ""
    ).replace(
        "\x00",
        "",
    )

    # --------------------------------------------------------
    # Plain text
    # --------------------------------------------------------

    if not is_html:

        message = MIMEText(
            final_body,
            "plain",
            "utf-8",
        )

    # --------------------------------------------------------
    # HTML + plain text alternative
    # --------------------------------------------------------

    else:

        message = MIMEMultipart(
            "alternative"
        )

        plain_part = MIMEText(
            html_to_plain_text(
                final_body
            ),
            "plain",
            "utf-8",
        )

        html_part = MIMEText(
            final_body,
            "html",
            "utf-8",
        )

        message.attach(
            plain_part
        )

        message.attach(
            html_part
        )

    # --------------------------------------------------------
    # Standard headers
    # --------------------------------------------------------

    message["Subject"] = final_subject

    message["From"] = formataddr(
        (
            final_sender_name,
            gmail,
        )
    )

    message["To"] = final_recipient

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    message["MIME-Version"] = "1.0"

    return message


# ============================================================
# SMTP SEND
# ============================================================

def send_one_email(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    context = ssl.create_default_context()

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=subject,
        body=body,
        is_html=is_html,
        recipient=recipient,
    )

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT,
    ) as server:

        server.ehlo()

        server.login(
            gmail,
            app_password,
        )

        # No automatic retry after an uncertain SMTP result.
        # This avoids accidental duplicate messages.
        server.sendmail(
            gmail,
            [recipient],
            message.as_string(),
        )

    return {
        "email": recipient,
        "result": "sent",
    }


# ============================================================
# WORKER
# ============================================================

def recipient_worker(
    work_queue,
    event_queue,
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
):

    while True:

        recipient = work_queue.get()

        try:

            if recipient is None:
                return

            try:

                result = send_one_email(
                    gmail=gmail,
                    app_password=app_password,
                    sender_name=sender_name,
                    subject=subject,
                    body=body,
                    is_html=is_html,
                    recipient=recipient,
                )

                event_queue.put({
                    "email": recipient,
                    "result": result["result"],
                })

            except smtplib.SMTPAuthenticationError:

                event_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error": (
                        "Gmail authentication failed. "
                        "Check Gmail address and "
                        "Google App Password."
                    ),
                })

            except smtplib.SMTPRecipientsRefused:

                event_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error": (
                        "Recipient was refused by "
                        "Gmail SMTP."
                    ),
                })

            except (
                smtplib.SMTPConnectError,
                smtplib.SMTPServerDisconnected,
                TimeoutError,
                ConnectionError,
            ) as exc:

                event_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error": safe_error(
                        exc,
                        "SMTP connection or network timeout.",
                    ),
                })

            except smtplib.SMTPException as exc:

                event_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error": safe_error(
                        exc,
                        "SMTP error while sending.",
                    ),
                })

            except Exception as exc:

                event_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error": safe_error(
                        exc,
                        "Unexpected error while sending.",
                    ),
                })

            # ------------------------------------------------
            # Requested pacing
            # ------------------------------------------------

            if not work_queue.empty():

                time.sleep(
                    SEND_DELAY_SECONDS
                )

        finally:

            work_queue.task_done()


# ============================================================
# SEND BATCH
# ============================================================

@app.route(
    "/send-batch",
    methods=["POST"],
)
def send_batch():

    if not authenticated():

        return jsonify({
            "success": False,
            "message": "Authentication required.",
            "login_required": True,
        }), 401

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message": "Invalid JSON request.",
        }), 400

    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    sender_name = clean_header(
        data.get("sender_name", ""),
        MAX_SENDER_NAME_LENGTH,
    )

    gmail = clean_header(
        data.get("gmail", ""),
        MAX_EMAIL_LENGTH,
    )

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = clean_header(
        data.get("subject", ""),
        MAX_SUBJECT_LENGTH,
    )

    body = str(
        data.get("body", "")
    )

    is_html = (
        data.get("is_html", False)
        is True
    )

    recipients = data.get(
        "recipients",
        [],
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            "",
        )
    ).strip()

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    if not sender_name:

        return jsonify({
            "success": False,
            "message": (
                "Sender Name is required."
            ),
        }), 400

    if not valid_email(gmail):

        return jsonify({
            "success": False,
            "message": (
                "Enter a valid Gmail address."
            ),
        }), 400

    if not gmail.lower().endswith(
        "@gmail.com"
    ):

        return jsonify({
            "success": False,
            "message": (
                "Please use a Gmail address "
                "with Gmail SMTP."
            ),
        }), 400

    if not app_password:

        return jsonify({
            "success": False,
            "message": (
                "Google App Password is required."
            ),
        }), 400

    if not subject:

        return jsonify({
            "success": False,
            "message": (
                "Email subject is required."
            ),
        }), 400

    if not body.strip():

        return jsonify({
            "success": False,
            "message": (
                "Message body is required."
            ),
        }), 400

    if len(body) > MAX_BODY_LENGTH:

        return jsonify({
            "success": False,
            "message": (
                "Message body is too large."
            ),
        }), 400

    if not isinstance(
        recipients,
        list,
    ):

        return jsonify({
            "success": False,
            "message": (
                "Invalid recipient list."
            ),
        }), 400

    # --------------------------------------------------------
    # CLEAN RECIPIENTS
    # --------------------------------------------------------

    clean_recipients = []
    seen = set()

    for item in recipients:

        email = normalize_email(
            item
        )

        if not valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)

        clean_recipients.append(
            email
        )

        if len(clean_recipients) >= MAX_RECIPIENTS:
            break

    if not clean_recipients:

        return jsonify({
            "success": False,
            "message": (
                "No valid recipients found."
            ),
        }), 400

    # --------------------------------------------------------
    # REMOTE IP
    # --------------------------------------------------------

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )

    if forwarded_for:

        remote_ip = (
            forwarded_for
            .split(",", 1)[0]
            .strip()
        )

    else:

        remote_ip = request.remote_addr

    # --------------------------------------------------------
    # TURNSTILE
    # --------------------------------------------------------

    verified, verify_error = verify_turnstile(
        turnstile_token,
        remote_ip,
    )

    if not verified:

        return jsonify({
            "success": False,
            "message": verify_error,
        }), 403

    # ========================================================
    # STREAMING GENERATOR
    # ========================================================

    @stream_with_context
    def generate():

        total = len(
            clean_recipients
        )

        sent_count = 0
        failed_count = 0
        completed = 0

        work_queue = queue.Queue()
        event_queue = queue.Queue()

        # ----------------------------------------------------
        # Queue recipients
        # ----------------------------------------------------

        for recipient in clean_recipients:

            work_queue.put(
                recipient
            )

        # ----------------------------------------------------
        # Stop signals
        # ----------------------------------------------------

        for _ in range(
            MAX_PARALLEL_SENDS
        ):

            work_queue.put(None)

        # ----------------------------------------------------
        # Initial event
        # ----------------------------------------------------

        yield (
            json.dumps(
                {
                    "type": "start",
                    "total": total,
                    "sent": 0,
                    "failed": 0,
                    "remaining": total,
                },
                ensure_ascii=False,
            )
            + "\n"
        )

        # ----------------------------------------------------
        # Workers
        # ----------------------------------------------------

        workers = []

        for _ in range(
            MAX_PARALLEL_SENDS
        ):

            thread = threading.Thread(
                target=recipient_worker,
                kwargs={
                    "work_queue": work_queue,
                    "event_queue": event_queue,
                    "gmail": gmail,
                    "app_password": app_password,
                    "sender_name": sender_name,
                    "subject": subject,
                    "body": body,
                    "is_html": is_html,
                },
                daemon=True,
            )

            thread.start()

            workers.append(
                thread
            )

        # ----------------------------------------------------
        # Progress
        # ----------------------------------------------------

        while completed < total:

            event = event_queue.get()

            completed += 1

            if event["result"] == "sent":

                sent_count += 1

            else:

                failed_count += 1

            remaining = (
                total
                - sent_count
                - failed_count
            )

            progress = {
                "type": "progress",
                "email": event["email"],
                "result": event["result"],
                "total": total,
                "sent": sent_count,
                "failed": failed_count,
                "remaining": remaining,
            }

            if event.get("error"):

                progress["error"] = (
                    event["error"]
                )

            yield (
                json.dumps(
                    progress,
                    ensure_ascii=False,
                )
                + "\n"
            )

        # ----------------------------------------------------
        # Finish workers
        # ----------------------------------------------------

        work_queue.join()

        for thread in workers:

            thread.join(
                timeout=2
            )

        # ----------------------------------------------------
        # Complete
        # ----------------------------------------------------

        yield (
            json.dumps(
                {
                    "type": "complete",
                    "success": True,
                    "message": (
                        "Sending completed."
                    ),
                    "total": total,
                    "sent": sent_count,
                    "failed": failed_count,
                    "remaining": 0,
                },
                ensure_ascii=False,
            )
            + "\n"
        )

    # ========================================================
    # RESPONSE
    # ========================================================

    response = Response(
        generate(),
        content_type=(
            "application/x-ndjson; "
            "charset=utf-8"
        ),
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, "
        "must-revalidate, "
        "no-transform, max-age=0"
    )

    response.headers["Pragma"] = "no-cache"

    response.headers["Expires"] = "0"

    response.headers[
        "X-Accel-Buffering"
    ] = "no"

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    return response


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "YATENDRA Mail Console",
        "mailer": "Gmail SMTP",
        "parallel_sends": MAX_PARALLEL_SENDS,
        "send_delay": SEND_DELAY_SECONDS,
        "smtp_timeout": SMTP_TIMEOUT,
        "max_recipients": MAX_RECIPIENTS,
        "authenticated": authenticated(),
    })


# ============================================================
# LOCAL
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )

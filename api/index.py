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

import smtplib
import ssl
import re
import os
import json
import urllib.request
import urllib.parse
import secrets
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# =========================================================
# FLASK
# =========================================================

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

handler = app


# =========================================================
# ENVIRONMENT
# =========================================================

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


app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# =========================================================
# MAIL SETTINGS
# =========================================================

MAX_RECIPIENTS = 25

MAX_PARALLEL_SENDS = 3

SEND_DELAY_SECONDS = 1.8

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_BODY_LENGTH = 100_000
MAX_SUBJECT_LENGTH = 998
MAX_SENDER_NAME_LENGTH = 200
MAX_EMAIL_LENGTH = 254


# =========================================================
# EMAIL VALIDATION
# =========================================================

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


# =========================================================
# HEADER CLEANING
# =========================================================

def clean_header(value, max_length=998):

    value = str(value or "")

    value = value.replace("\r", " ")
    value = value.replace("\n", " ")

    return value.strip()[:max_length]


# =========================================================
# AUTH
# =========================================================

def authenticated():
    return session.get("authenticated") is True


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


# =========================================================
# TURNSTILE
# =========================================================

def verify_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET_KEY:
        return False, (
            "TURNSTILE_SECRET_KEY is not configured."
        )

    if not token:
        return False, (
            "Cloudflare verification is required."
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
                "application/x-www-form-urlencoded"
        },
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=10,
        ) as response:

            result = json.loads(
                response.read().decode(
                    "utf-8",
                    errors="replace",
                )
            )

        if result.get("success") is True:
            return True, None

        return False, (
            "Cloudflare verification failed."
        )

    except Exception:
        return False, (
            "Unable to verify Cloudflare."
        )


# =========================================================
# LOGIN
# =========================================================

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


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if not authenticated():
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# =========================================================
# HTML TO TEXT
# =========================================================

def html_to_plain_text(html):

    text = str(html or "")

    text = re.sub(
        r"<(script|style)\b[^>]*>.*?</\1>",
        "",
        text,
        flags=re.I | re.S,
    )

    text = re.sub(
        r"<br\s*/?>",
        "\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"</(p|div|li|tr|h[1-6])\s*>",
        "\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text,
    )

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


# =========================================================
# BUILD MESSAGE
# =========================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    body = str(body or "").replace(
        "\x00",
        "",
    )

    if is_html:

        message = MIMEMultipart(
            "alternative"
        )

        plain_body = html_to_plain_text(
            body
        )

        if not plain_body:
            plain_body = (
                "This message contains HTML content."
            )

        message.attach(
            MIMEText(
                plain_body,
                "plain",
                "utf-8",
            )
        )

        message.attach(
            MIMEText(
                body,
                "html",
                "utf-8",
            )
        )

    else:

        message = MIMEText(
            body,
            "plain",
            "utf-8",
        )

    message["Subject"] = clean_header(
        subject,
        MAX_SUBJECT_LENGTH,
    )

    message["From"] = formataddr(
        (
            clean_header(
                sender_name,
                MAX_SENDER_NAME_LENGTH,
            ),
            gmail,
        )
    )

    message["To"] = clean_header(
        recipient,
        MAX_EMAIL_LENGTH,
    )

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    message["MIME-Version"] = "1.0"

    return message


# =========================================================
# ONE SMTP WORKER
# =========================================================

def send_worker(
    worker_id,
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipients,
):
    """
    Each worker owns its own SMTP connection.
    Connections are reused for that worker's messages.
    """

    results = []

    server = None

    try:

        context = ssl.create_default_context()

        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=SMTP_TIMEOUT,
        )

        server.ehlo()

        server.login(
            gmail,
            app_password,
        )

        for index, recipient in enumerate(
            recipients
        ):

            try:

                message = build_message(
                    gmail=gmail,
                    sender_name=sender_name,
                    subject=subject,
                    body=body,
                    is_html=is_html,
                    recipient=recipient,
                )

                # SMTP accepted the message for
                # this recipient.
                server.sendmail(
                    gmail,
                    [recipient],
                    message.as_string(),
                )

                results.append({
                    "email": recipient,
                    "result": "sent",
                    "worker": worker_id,
                })

            except smtplib.SMTPRecipientsRefused as exc:

                results.append({
                    "email": recipient,
                    "result": "failed",
                    "error":
                        "Recipient was refused by Gmail SMTP.",
                    "worker": worker_id,
                })

            except smtplib.SMTPAuthenticationError:

                results.append({
                    "email": recipient,
                    "result": "failed",
                    "error":
                        "Gmail authentication failed. Check Gmail and App Password.",
                    "worker": worker_id,
                })

                # Authentication will not become valid
                # during this batch.
                break

            except (
                smtplib.SMTPServerDisconnected,
                smtplib.SMTPConnectError,
                TimeoutError,
                ConnectionError,
            ) as exc:

                results.append({
                    "email": recipient,
                    "result": "failed",
                    "error":
                        str(exc)[:300]
                        or "SMTP connection error.",
                    "worker": worker_id,
                })

                # Do not automatically retry a send after
                # an uncertain SMTP state; this prevents
                # accidental duplicate messages.
                break

            except smtplib.SMTPException as exc:

                results.append({
                    "email": recipient,
                    "result": "failed",
                    "error":
                        str(exc)[:300]
                        or "SMTP error.",
                    "worker": worker_id,
                })

            except Exception as exc:

                results.append({
                    "email": recipient,
                    "result": "failed",
                    "error":
                        str(exc)[:300]
                        or "Unexpected sending error.",
                    "worker": worker_id,
                })

            # Controlled per-worker pacing.
            if index < len(recipients) - 1:
                time.sleep(
                    SEND_DELAY_SECONDS
                )

    except smtplib.SMTPAuthenticationError:

        for recipient in recipients:

            results.append({
                "email": recipient,
                "result": "failed",
                "error":
                    "Gmail authentication failed. Check Gmail and App Password.",
                "worker": worker_id,
            })

    except Exception as exc:

        error_text = str(exc).strip()

        if not error_text:
            error_text = (
                "SMTP connection failed."
            )

        # Only recipients not already reported.
        reported = {
            item["email"]
            for item in results
        }

        for recipient in recipients:

            if recipient in reported:
                continue

            results.append({
                "email": recipient,
                "result": "failed",
                "error": error_text[:300],
                "worker": worker_id,
            })

    finally:

        if server is not None:

            try:
                server.quit()

            except Exception:

                try:
                    server.close()
                except Exception:
                    pass

    return results


# =========================================================
# SEND BATCH
# =========================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():

    if not authenticated():

        return jsonify({
            "success": False,
            "message":
                "Authentication required.",
            "login_required": True,
        }), 401

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message":
                "Invalid JSON request.",
        }), 400

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
        data.get("is_html", False) is True
    )

    recipients_input = data.get(
        "recipients",
        [],
    )

    turnstile_token = str(
        data.get("turnstile_token", "")
    ).strip()

    # =====================================================
    # VALIDATION
    # =====================================================

    if not sender_name:

        return jsonify({
            "success": False,
            "message":
                "Sender Name is required.",
        }), 400

    if not valid_email(gmail):

        return jsonify({
            "success": False,
            "message":
                "Enter a valid Gmail address.",
        }), 400

    if not gmail.lower().endswith(
        "@gmail.com"
    ):

        return jsonify({
            "success": False,
            "message":
                "Please use a Gmail address.",
        }), 400

    if not app_password:

        return jsonify({
            "success": False,
            "message":
                "Google App Password is required.",
        }), 400

    if not subject:

        return jsonify({
            "success": False,
            "message":
                "Email subject is required.",
        }), 400

    if not body.strip():

        return jsonify({
            "success": False,
            "message":
                "Message body is required.",
        }), 400

    if len(body) > MAX_BODY_LENGTH:

        return jsonify({
            "success": False,
            "message":
                "Message body is too large.",
        }), 400

    if not isinstance(
        recipients_input,
        list,
    ):

        return jsonify({
            "success": False,
            "message":
                "Invalid recipient list.",
        }), 400

    # =====================================================
    # RECIPIENTS
    # =====================================================

    clean_recipients = []
    seen = set()
    invalid = []

    for item in recipients_input:

        email = normalize_email(item)

        if not email:
            continue

        if not valid_email(email):

            invalid.append(email)
            continue

        if email in seen:
            continue

        seen.add(email)
        clean_recipients.append(email)

    if invalid:

        return jsonify({
            "success": False,
            "message":
                "One or more recipient addresses are invalid.",
            "invalid":
                invalid[:10],
        }), 400

    if not clean_recipients:

        return jsonify({
            "success": False,
            "message":
                "No valid recipients found.",
        }), 400

    if len(clean_recipients) > MAX_RECIPIENTS:

        return jsonify({
            "success": False,
            "message":
                f"Maximum {MAX_RECIPIENTS} recipients are allowed.",
        }), 400

    # =====================================================
    # TURNSTILE
    # =====================================================

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

    verified, verify_error = verify_turnstile(
        turnstile_token,
        remote_ip,
    )

    if not verified:

        return jsonify({
            "success": False,
            "message":
                verify_error,
        }), 403

    # =====================================================
    # SPLIT RECIPIENTS
    # =====================================================

    worker_count = min(
        MAX_PARALLEL_SENDS,
        len(clean_recipients),
    )

    worker_lists = [
        []
        for _ in range(worker_count)
    ]

    for index, email in enumerate(
        clean_recipients
    ):

        worker_lists[
            index % worker_count
        ].append(email)

    # =====================================================
    # STREAM
    # =====================================================

    @stream_with_context
    def generate():

        total = len(
            clean_recipients
        )

        sent_count = 0
        failed_count = 0

        yield (
            json.dumps({
                "type": "start",
                "total": total,
                "sent": 0,
                "failed": 0,
                "remaining": total,
                "parallel": worker_count,
                "status": "sending",
            }, ensure_ascii=False)
            + "\n"
        )

        futures = {}

        with ThreadPoolExecutor(
            max_workers=worker_count
        ) as executor:

            for worker_id, recipient_list in enumerate(
                worker_lists,
                start=1,
            ):

                future = executor.submit(
                    send_worker,
                    worker_id,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient_list,
                )

                futures[future] = worker_id

            for future in as_completed(
                futures
            ):

                worker_id = futures[future]

                try:
                    results = future.result()

                except Exception as exc:

                    results = []

                    error_text = (
                        str(exc).strip()
                        or "Worker failed."
                    )

                    for email in worker_lists[
                        worker_id - 1
                    ]:

                        results.append({
                            "email": email,
                            "result": "failed",
                            "error":
                                error_text[:300],
                            "worker":
                                worker_id,
                        })

                for result in results:

                    if result.get(
                        "result"
                    ) == "sent":

                        sent_count += 1

                    else:

                        failed_count += 1

                    remaining = (
                        total
                        - sent_count
                        - failed_count
                    )

                    yield (
                        json.dumps({
                            "type":
                                "progress",

                            "email":
                                result.get(
                                    "email"
                                ),

                            "result":
                                result.get(
                                    "result"
                                ),

                            "error":
                                result.get(
                                    "error"
                                ),

                            "total":
                                total,

                            "sent":
                                sent_count,

                            "failed":
                                failed_count,

                            "remaining":
                                remaining,

                            "worker":
                                result.get(
                                    "worker"
                                ),

                            "status":
                                "sending",
                        }, ensure_ascii=False)
                        + "\n"
                    )

        yield (
            json.dumps({
                "type":
                    "complete",

                "success":
                    failed_count == 0,

                "total":
                    total,

                "sent":
                    sent_count,

                "failed":
                    failed_count,

                "remaining":
                    total
                    - sent_count
                    - failed_count,

                "status":
                    "complete",

                "message":
                    "Sending completed.",
            }, ensure_ascii=False)
            + "\n"
        )

    response = Response(
        generate(),
        content_type=(
            "application/x-ndjson; charset=utf-8"
        ),
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate, "
        "no-transform, max-age=0"
    )

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["X-Content-Type-Options"] = "nosniff"

    return response


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "mailer": "Gmail SMTP",
        "parallel_sends":
            MAX_PARALLEL_SENDS,
        "delay_seconds":
            SEND_DELAY_SECONDS,
        "max_recipients":
            MAX_RECIPIENTS,
    })


# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )

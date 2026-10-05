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

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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
# ENVIRONMENT VARIABLES
# =========================================================

SESSION_SECRET = os.environ.get(
    "SESSION_SECRET",
    "",
).strip()

LOGIN_PASSWORD = os.environ.get(
    "LOGIN_PASSWORD",
    "",
).strip()

TURNSTILE_SITE_KEY = os.environ.get(
    "TURNSTILE_SITE_KEY",
    "",
).strip()

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    "",
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


# =========================================================
# SESSION CONFIG
# =========================================================

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# =========================================================
# MAIL CONFIG
# =========================================================

MAX_RECIPIENTS = 25

MAX_PARALLEL_SENDS = 3

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# This controls the pace of each worker.
# It is not a spam-filter bypass mechanism.
SEND_DELAY_SECONDS = 1.8


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

    if len(value) > 254:
        return False

    return bool(
        EMAIL_RE.fullmatch(value)
    )


def normalize_email(value):
    return str(value or "").strip().lower()


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

    return redirect(
        url_for("login")
    )


# =========================================================
# HEADER CLEANING
# =========================================================

def clean_header(
    value,
    max_length=998,
):
    value = str(value or "")

    # Prevent header injection.
    value = value.replace("\r", " ")
    value = value.replace("\n", " ")

    value = value.strip()

    return value[:max_length]


# =========================================================
# TURNSTILE
# =========================================================

def verify_turnstile(
    token,
    remote_ip=None,
):

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
                response
                .read()
                .decode("utf-8")
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


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():

    if authenticated():
        return redirect(
            url_for("home")
        )

    if request.method == "GET":

        return render_template(
            "login.html",
            error=None,
            turnstile_site_key=TURNSTILE_SITE_KEY,
        )

    password = str(
        request.form.get(
            "password",
            "",
        )
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

    return redirect(
        url_for("home")
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout",
    methods=["GET", "POST"],
)
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if not authenticated():
        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# =========================================================
# HTML -> PLAIN TEXT
# =========================================================

def html_to_plain_text(html):

    text = str(html or "")

    text = re.sub(
        r"<br\s*/?>",
        "\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"</p\s*>",
        "\n\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"</div\s*>",
        "\n",
        text,
        flags=re.I,
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text,
    )

    text = (
        text
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )

    return text.strip()


# =========================================================
# BUILD EMAIL
# =========================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    gmail = gmail.strip().lower()

    recipient = recipient.strip()

    sender_name = clean_header(
        sender_name,
        max_length=200,
    )

    subject = clean_header(
        subject,
        max_length=998,
    )

    body = (
        str(body or "")
        .replace("\x00", "")
    )

    # -----------------------------------------------------
    # HTML EMAIL
    # -----------------------------------------------------

    if is_html:

        message = MIMEMultipart(
            "alternative"
        )

        plain_body = html_to_plain_text(
            body
        )

        plain_part = MIMEText(
            plain_body,
            "plain",
            "utf-8",
        )

        html_part = MIMEText(
            body,
            "html",
            "utf-8",
        )

        message.attach(
            plain_part
        )

        message.attach(
            html_part
        )

    # -----------------------------------------------------
    # PLAIN TEXT EMAIL
    # -----------------------------------------------------

    else:

        message = MIMEText(
            body,
            "plain",
            "utf-8",
        )

    # -----------------------------------------------------
    # STANDARD HEADERS
    # -----------------------------------------------------

    message["Subject"] = subject

    # Important:
    # The authenticated Gmail account is also the
    # envelope sender / From address.
    message["From"] = formataddr(
        (
            sender_name,
            gmail,
        )
    )

    message["To"] = recipient

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    return message


# =========================================================
# SEND ONE EMAIL
# =========================================================

def send_one_email(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    # Small pacing delay.
    if SEND_DELAY_SECONDS > 0:
        time.sleep(
            SEND_DELAY_SECONDS
        )

    context = ssl.create_default_context()

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=subject,
        body=body,
        is_html=is_html,
        recipient=recipient,
    )

    # Gmail App Passwords are sometimes copied
    # with spaces. Removing whitespace makes the
    # login input more tolerant without storing it.
    clean_app_password = re.sub(
        r"\s+",
        "",
        app_password,
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
            clean_app_password,
        )

        refused = server.sendmail(
            gmail,
            [recipient],
            message.as_string(),
        )

        # sendmail() normally returns {}
        # when the recipient was accepted.
        if refused:

            return {
                "email": recipient,
                "result": "failed",
                "error": (
                    "SMTP refused recipient."
                ),
            }

    return {
        "email": recipient,
        "result": "sent",
    }


# =========================================================
# SEND BATCH
# =========================================================

@app.route(
    "/send-batch",
    methods=["POST"],
)
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

    # -----------------------------------------------------
    # INPUTS
    # -----------------------------------------------------

    sender_name = clean_header(
        data.get(
            "sender_name",
            "",
        ),
        max_length=200,
    )

    gmail = clean_header(
        data.get(
            "gmail",
            "",
        ),
        max_length=254,
    )

    app_password = str(
        data.get(
            "app_password",
            "",
        )
    ).strip()

    subject = clean_header(
        data.get(
            "subject",
            "",
        ),
        max_length=998,
    )

    body = str(
        data.get(
            "body",
            "",
        )
    )

    is_html = (
        data.get(
            "is_html",
            False,
        ) is True
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

    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

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
                "Please use a Gmail address with Gmail SMTP.",
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

    if len(body) > 100_000:

        return jsonify({
            "success": False,
            "message":
                "Message body is too large.",
        }), 400

    if not isinstance(
        recipients,
        list,
    ):

        return jsonify({
            "success": False,
            "message":
                "Invalid recipient list.",
        }), 400

    # -----------------------------------------------------
    # CLEAN RECIPIENTS
    # -----------------------------------------------------

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

    clean_recipients = (
        clean_recipients[
            :MAX_RECIPIENTS
        ]
    )

    if not clean_recipients:

        return jsonify({
            "success": False,
            "message":
                "No valid recipients found.",
        }), 400

    # -----------------------------------------------------
    # TURNSTILE
    # -----------------------------------------------------

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

    verified, verify_error = (
        verify_turnstile(
            turnstile_token,
            remote_ip,
        )
    )

    if not verified:

        return jsonify({
            "success": False,
            "message": verify_error,
        }), 403

    # =====================================================
    # STREAMING GENERATOR
    # =====================================================

    @stream_with_context
    def generate():

        total = len(
            clean_recipients
        )

        sent_count = 0

        failed_count = 0

        # -------------------------------------------------
        # START EVENT
        # -------------------------------------------------

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

        executor = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        )

        future_map = {}

        try:

            # ---------------------------------------------
            # SUBMIT JOBS
            # ---------------------------------------------

            for recipient in clean_recipients:

                future = executor.submit(
                    send_one_email,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient,
                )

                future_map[
                    future
                ] = recipient

            # ---------------------------------------------
            # PROCESS COMPLETED JOBS
            # ---------------------------------------------

            for future in as_completed(
                future_map
            ):

                recipient = future_map[
                    future
                ]

                try:

                    result = future.result()

                    if (
                        result.get("result")
                        == "sent"
                    ):

                        sent_count += 1

                        yield (
                            json.dumps(
                                {
                                    "type":
                                        "progress",
                                    "email":
                                        recipient,
                                    "result":
                                        "sent",
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
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        )

                    else:

                        failed_count += 1

                        yield (
                            json.dumps(
                                {
                                    "type":
                                        "progress",
                                    "email":
                                        recipient,
                                    "result":
                                        "failed",
                                    "error":
                                        result.get(
                                            "error",
                                            "SMTP delivery failed.",
                                        ),
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
                                },
                                ensure_ascii=False,
                            )
                            + "\n"
                        )

                # -----------------------------------------
                # AUTH ERROR
                # -----------------------------------------

                except smtplib.SMTPAuthenticationError:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "email":
                                    recipient,
                                "result":
                                    "failed",
                                "error":
                                    "Gmail authentication failed. Check the Gmail address and App Password.",
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
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                # -----------------------------------------
                # RECIPIENT REFUSED
                # -----------------------------------------

                except smtplib.SMTPRecipientsRefused:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "email":
                                    recipient,
                                "result":
                                    "failed",
                                "error":
                                    "SMTP recipient was refused.",
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
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                # -----------------------------------------
                # CONNECTION / TIMEOUT
                # -----------------------------------------

                except (
                    smtplib.SMTPConnectError,
                    smtplib.SMTPServerDisconnected,
                    TimeoutError,
                    ConnectionError,
                ):

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "email":
                                    recipient,
                                "result":
                                    "failed",
                                "error":
                                    "SMTP connection or timeout error.",
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
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                # -----------------------------------------
                # GENERIC SMTP ERROR
                # -----------------------------------------

                except smtplib.SMTPException as exc:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "email":
                                    recipient,
                                "result":
                                    "failed",
                                "error":
                                    str(exc)[:500],
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
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                # -----------------------------------------
                # UNEXPECTED ERROR
                # -----------------------------------------

                except Exception as exc:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "email":
                                    recipient,
                                "result":
                                    "failed",
                                "error":
                                    str(exc)[:500],
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
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

        finally:

            executor.shutdown(
                wait=True
            )

        # -------------------------------------------------
        # COMPLETE
        # -------------------------------------------------

        yield (
            json.dumps(
                {
                    "type":
                        "complete",
                    "success":
                        True,
                    "message":
                        "Sending completed.",
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
                },
                ensure_ascii=False,
            )
            + "\n"
        )

    # =====================================================
    # STREAM RESPONSE
    # =====================================================

    response = Response(
        generate(),
        content_type=(
            "application/x-ndjson; "
            "charset=utf-8"
        ),
    )

    response.headers[
        "Cache-Control"
    ] = (
        "no-cache, "
        "no-store, "
        "must-revalidate, "
        "no-transform, "
        "max-age=0"
    )

    response.headers[
        "Pragma"
    ] = "no-cache"

    response.headers[
        "Expires"
    ] = "0"

    response.headers[
        "X-Accel-Buffering"
    ] = "no"

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    return response


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service":
            "YATENDRA Mail Console",
        "mailer":
            "Gmail SMTP",
        "content_variation":
            False,
        "parallel_sends":
            MAX_PARALLEL_SENDS,
        "send_delay":
            SEND_DELAY_SECONDS,
        "max_recipients":
            MAX_RECIPIENTS,
        "authenticated":
            authenticated(),
    })


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )

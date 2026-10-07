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
import secrets
import time

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid


# ============================================================
# PATHS / FLASK
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

# Vercel
handler = app


# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

SESSION_SECRET = os.environ.get(
    "SESSION_SECRET",
    "",
).strip()

LOGIN_PASSWORD = os.environ.get(
    "LOGIN_PASSWORD",
    "",
).strip()

# Keep these in Vercel if you want.
# They are optional in this version.
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
        "SESSION_SECRET is not configured."
    )

if not LOGIN_PASSWORD:
    raise RuntimeError(
        "LOGIN_PASSWORD is not configured."
    )


# ============================================================
# SESSION SECURITY
# ============================================================

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# ============================================================
# MAIL SETTINGS
# ============================================================

MAX_RECIPIENTS = 25

# Controlled concurrency.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# Delay between sends handled by workers.
SEND_DELAY_SECONDS = 1.8


# ============================================================
# EMAIL VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def normalize_email(value):
    return str(value or "").strip().lower()


def valid_email(value):
    value = normalize_email(value)

    if not value:
        return False

    if len(value) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(value))


# ============================================================
# AUTH
# ============================================================

def authenticated():
    return session.get("authenticated") is True


@app.before_request
def require_login():

    allowed_endpoints = {
        "login",
        "health",
        "static",
    }

    if request.endpoint in allowed_endpoints:
        return None

    if authenticated():
        return None

    if request.path.startswith("/send"):
        return jsonify({
            "success": False,
            "message": "Authentication required.",
            "login_required": True,
        }), 401

    return redirect(url_for("login"))


# ============================================================
# HEADER CLEANING
# ============================================================

def clean_header(value, max_length=998):

    value = str(value or "")

    # Prevent header injection.
    value = value.replace("\r", " ")
    value = value.replace("\n", " ")

    value = value.strip()

    return value[:max_length]


# ============================================================
# PERSONALIZATION
# ============================================================

def personalize_template(template, recipient):

    result = str(template or "")

    replacements = {
        "{{hi}}": str(recipient.get("hi", "")),
        "{{hello}}": str(recipient.get("hello", "")),
        "{{thanks}}": str(recipient.get("thanks", "")),
        "{{name}}": str(recipient.get("name", "")),
        "{{email}}": str(recipient.get("email", "")),
        "{{ref_code}}": str(recipient.get("ref_code", "")),
    }

    for key, value in replacements.items():
        result = result.replace(key, value)

    return result


# ============================================================
# HTML TO TEXT
# ============================================================

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
        r"</li\s*>",
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


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if authenticated():
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":

        password = str(
            request.form.get(
                "password",
                "",
            )
        )

        # Turnstile intentionally optional.
        # Existing Turnstile environment variables
        # do not block login.

        if not secrets.compare_digest(
            password,
            LOGIN_PASSWORD,
        ):
            error = "Incorrect password."

        else:

            session.clear()

            session.permanent = True

            session["authenticated"] = True

            return redirect(
                url_for("home")
            )

    return render_template(
        "login.html",
        error=error,
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# HOME
# ============================================================

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


# ============================================================
# MIME MESSAGE
# ============================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    gmail = normalize_email(gmail)
    recipient = normalize_email(recipient)

    sender_name = clean_header(
        sender_name,
        200,
    )

    subject = clean_header(
        subject,
        998,
    )

    body = str(body or "").replace(
        "\x00",
        "",
    )

    if is_html:

        message = MIMEMultipart(
            "alternative"
        )

        plain_text = html_to_plain_text(
            body
        )

        message.attach(
            MIMEText(
                plain_text,
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

    # IMPORTANT:
    # Always use the authenticated Gmail account
    # as the actual From address.
    message["From"] = formataddr(
        (
            sender_name,
            gmail,
        )
    )

    message["To"] = recipient

    message["Subject"] = subject

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    message["MIME-Version"] = "1.0"

    return message


# ============================================================
# RECIPIENT NORMALIZATION
# ============================================================

def normalize_recipient(item):

    if isinstance(item, str):

        return {
            "email": normalize_email(item),
            "name": "",
            "hi": "",
            "hello": "",
            "thanks": "",
            "ref_code": "",
        }

    if not isinstance(item, dict):
        return None

    email = normalize_email(
        item.get("email", "")
    )

    if not email:
        return None

    def clean_text(value, limit):

        value = str(value or "")

        value = value.replace(
            "\r",
            " ",
        )

        value = value.replace(
            "\n",
            " ",
        )

        return value.strip()[:limit]

    return {
        "email": email,
        "name": clean_text(
            item.get("name"),
            200,
        ),
        "hi": clean_text(
            item.get("hi"),
            100,
        ),
        "hello": clean_text(
            item.get("hello"),
            100,
        ),
        "thanks": clean_text(
            item.get("thanks"),
            100,
        ),
        "ref_code": clean_text(
            item.get("ref_code"),
            200,
        ),
    }


# ============================================================
# SEND ONE EMAIL
# ============================================================

def send_one_email(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient_data,
):

    recipient = normalize_email(
        recipient_data.get(
            "email",
            "",
        )
    )

    # Google App Password is sometimes copied
    # with spaces.
    clean_app_password = re.sub(
        r"\s+",
        "",
        str(app_password or ""),
    )

    personalized_subject = (
        personalize_template(
            subject,
            recipient_data,
        )
    )

    personalized_body = (
        personalize_template(
            body,
            recipient_data,
        )
    )

    if SEND_DELAY_SECONDS > 0:
        time.sleep(
            SEND_DELAY_SECONDS
        )

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=personalized_subject,
        body=personalized_body,
        is_html=is_html,
        recipient=recipient,
    )

    # TLS encrypted SMTP connection.
    context = ssl.create_default_context()

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

        if refused:

            return {
                "email": recipient,
                "result": "failed",
                "error":
                    "SMTP recipient was refused.",
            }

    return {
        "email": recipient,
        "result": "sent",
    }


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

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify({
            "success": False,
            "message": "Invalid JSON request.",
        }), 400

    sender_name = clean_header(
        data.get(
            "sender_name",
            "",
        ),
        200,
    )

    gmail = normalize_email(
        data.get(
            "gmail",
            "",
        )
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
        998,
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
        )
        is True
    )

    recipients = data.get(
        "recipients",
        [],
    )

    # Frontend can still send this field.
    # It is ignored because Turnstile is optional.
    _turnstile_token = str(
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
            "message":
                "Sender Name is required.",
        }), 400

    if not valid_email(gmail):

        return jsonify({
            "success": False,
            "message":
                "Enter a valid Gmail address.",
        }), 400

    if not gmail.endswith("@gmail.com"):

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

    # --------------------------------------------------------
    # CLEAN + DEDUPLICATE
    # --------------------------------------------------------

    clean_recipients = []

    seen = set()

    for item in recipients:

        recipient = normalize_recipient(
            item
        )

        if not recipient:
            continue

        email = recipient["email"]

        if not valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)

        clean_recipients.append(
            recipient
        )

        if len(clean_recipients) >= MAX_RECIPIENTS:
            break

    if not clean_recipients:

        return jsonify({
            "success": False,
            "message":
                "No valid recipients found.",
        }), 400

    # ========================================================
    # STREAMING
    # ========================================================

    @stream_with_context
    def generate():

        total = len(
            clean_recipients
        )

        sent_count = 0
        failed_count = 0

        # ----------------------------------------------------
        # START EVENT
        # ----------------------------------------------------

        yield (
            json.dumps(
                {
                    "type": "start",
                    "total": total,
                    "sent": 0,
                    "failed": 0,
                    "remaining": total,
                    "parallel":
                        MAX_PARALLEL_SENDS,
                    "delay":
                        SEND_DELAY_SECONDS,
                },
                ensure_ascii=False,
            )
            + "\n"
        )

        executor = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        )

        futures = {}

        try:

            # ------------------------------------------------
            # SUBMIT EMAILS
            # ------------------------------------------------

            for recipient_data in clean_recipients:

                future = executor.submit(
                    send_one_email,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient_data,
                )

                futures[future] = (
                    recipient_data
                )

            # ------------------------------------------------
            # LIVE COMPLETION
            # ------------------------------------------------

            for future in as_completed(
                futures
            ):

                recipient_data = futures[
                    future
                ]

                email = recipient_data[
                    "email"
                ]

                try:

                    result = future.result()

                    if result.get(
                        "result"
                    ) == "sent":

                        sent_count += 1

                        yield (
                            json.dumps(
                                {
                                    "type":
                                        "progress",
                                    "email":
                                        email,
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
                                        email,
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

                except smtplib.SMTPAuthenticationError:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "email":
                                    email,
                                "result":
                                    "failed",
                                "error":
                                    "Gmail authentication failed. Check Gmail/App Password.",
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
                            }
                        )
                        + "\n"
                    )

                except smtplib.SMTPRecipientsRefused:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "email":
                                    email,
                                "result":
                                    "failed",
                                "error":
                                    "Recipient was refused by SMTP server.",
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
                            }
                        )
                        + "\n"
                    )

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
                                    email,
                                "result":
                                    "failed",
                                "error":
                                    "SMTP connection/timeout error.",
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
                            }
                        )
                        + "\n"
                    )

                except smtplib.SMTPException as exc:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "email":
                                    email,
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
                            }
                        )
                        + "\n"
                    )

                except Exception as exc:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "email":
                                    email,
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
                            }
                        )
                        + "\n"
                    )

        finally:

            executor.shutdown(
                wait=True
            )

        # ----------------------------------------------------
        # COMPLETE
        # ----------------------------------------------------

        yield (
            json.dumps(
                {
                    "type":
                        "complete",
                    "success":
                        failed_count == 0,
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


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "YATENDRA Mail Console",
        "smtp": SMTP_HOST,
        "tls": True,
        "parallel_sends":
            MAX_PARALLEL_SENDS,
        "delay":
            SEND_DELAY_SECONDS,
        "max_recipients":
            MAX_RECIPIENTS,
        "turnstile_required":
            False,
    })


# ============================================================
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000,
            )
        ),
        debug=False,
    )

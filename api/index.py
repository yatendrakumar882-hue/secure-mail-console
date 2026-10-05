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
import random
import time

from concurrent.futures import ThreadPoolExecutor, as_completed

from email.mime.text import MIMEText
from email.utils import (
    formataddr,
    formatdate,
    make_msgid,
)

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
# SECURITY / ENVIRONMENT
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
        "SESSION_SECRET is not configured."
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

# Exactly two simultaneous SMTP tasks.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# ---------------------------------------------------------
# Slightly slower than the current configuration.
#
# Current: 1.8 seconds
# New:     2.5 seconds
#
# Delay is applied AFTER a successful send, before that
# worker processes its next recipient.
# ---------------------------------------------------------

SEND_DELAY_SECONDS = 2.5


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):

    try:
        value = str(value).strip()
    except Exception:
        return False

    if not value:
        return False

    if len(value) > 254:
        return False

    return bool(
        EMAIL_RE.fullmatch(value)
    )


# =========================================================
# AUTH
# =========================================================

def authenticated():

    return (
        session.get("authenticated") is True
    )


@app.before_request
def require_login():

    # Public endpoints.
    if request.endpoint in {
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

def clean_header(value):

    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()
    )


# =========================================================
# SPINTAX
# =========================================================

SPINTAX_RE = re.compile(
    r"\{([^{}]+)\}"
)


def expand_spintax(text):

    if not isinstance(text, str):
        text = str(text or "")

    def replace_match(match):

        options = [
            option.strip()
            for option in match.group(1).split("|")
            if option.strip()
        ]

        if len(options) < 2:
            return match.group(0)

        return random.choice(options)

    return SPINTAX_RE.sub(
        replace_match,
        text,
    )


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

    # Never authenticate if the environment variable
    # is missing.
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

    # Rotate the session after successful login.
    session.clear()

    session.permanent = True

    session["authenticated"] = True

    return redirect(
        url_for("home")
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
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
# BUILD CLEAN EMAIL
# =========================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    final_subject = expand_spintax(
        clean_header(subject)
    )

    final_body = expand_spintax(
        body
    )

    content_type = (
        "html"
        if is_html
        else "plain"
    )

    message = MIMEText(
        final_body,
        content_type,
        "utf-8",
    )

    # -----------------------------------------------------
    # Standard legitimate email headers.
    # No forged or filtering-evasion headers.
    # -----------------------------------------------------

    message["Subject"] = final_subject

    message["From"] = formataddr(
        (
            clean_header(sender_name),
            gmail,
        )
    )

    message["To"] = recipient

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    message["MIME-Version"] = "1.0"

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

    context = ssl.create_default_context()

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=subject,
        body=body,
        is_html=is_html,
        recipient=recipient,
    )

    server = None

    try:

        # -------------------------------------------------
        # New authenticated Gmail SMTP connection.
        # -------------------------------------------------

        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=SMTP_TIMEOUT,
        )

        # -------------------------------------------------
        # Gmail authentication.
        # -------------------------------------------------

        server.login(
            gmail,
            app_password,
        )

        # -------------------------------------------------
        # Send exactly one recipient.
        # -------------------------------------------------

        server.sendmail(
            gmail,
            [recipient],
            message.as_string(),
        )

        # -------------------------------------------------
        # Controlled pacing.
        #
        # This is intentionally AFTER the successful send,
        # so the first two emails are not unnecessarily
        # delayed.
        # -------------------------------------------------

        time.sleep(
            SEND_DELAY_SECONDS
        )

        return {
            "email": recipient,
            "result": "sent",
        }

    finally:

        if server is not None:

            try:

                server.quit()

            except Exception:

                try:
                    server.close()

                except Exception:
                    pass


# =========================================================
# SEND BATCH
# =========================================================

@app.route(
    "/send-batch",
    methods=["POST"],
)
def send_batch():

    # Defense in depth.
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
        data = {}

    # =====================================================
    # INPUTS
    # =====================================================

    sender_name = clean_header(
        data.get(
            "sender_name",
            "",
        )
    )

    gmail = clean_header(
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
        )
    )

    body = str(
        data.get(
            "body",
            "",
        )
    )

    is_html = bool(
        data.get(
            "is_html",
            False,
        )
    )

    recipients = data.get(
        "recipients",
        []
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            "",
        )
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


    if not isinstance(
        recipients,
        list,
    ):

        return jsonify({
            "success": False,
            "message":
                "Invalid recipient list.",
        }), 400


    # =====================================================
    # CLEAN RECIPIENTS
    # =====================================================

    clean_recipients = []

    seen = set()

    for item in recipients:

        email = str(
            item
        ).strip().lower()

        if not valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)

        clean_recipients.append(
            email
        )

    clean_recipients = clean_recipients[
        :MAX_RECIPIENTS
    ]


    if not clean_recipients:

        return jsonify({
            "success": False,
            "message":
                "No valid recipients found.",
        }), 400


    # =====================================================
    # TURNSTILE
    # =====================================================

    forwarded_for = request.headers.get(
        "X-Forwarded-For"
    )

    remote_ip = (
        forwarded_for.split(",")[0].strip()
        if forwarded_for
        else request.remote_addr
    )

    verified, verify_error = verify_turnstile(
        turnstile_token,
        remote_ip,
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
                    "parallel":
                        MAX_PARALLEL_SENDS,
                    "delay":
                        SEND_DELAY_SECONDS,
                },
                ensure_ascii=False,
            ) + "\n"
        )


        # =================================================
        # TWO PARALLEL SENDS
        # =================================================

        executor = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        )

        future_map = {}

        try:

            # -------------------------------------------------
            # Submit all recipients.
            #
            # ThreadPoolExecutor ensures only two are
            # executing simultaneously.
            # -------------------------------------------------

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


            # -------------------------------------------------
            # Emit each completed email immediately.
            # -------------------------------------------------

            for future in as_completed(
                future_map
            ):

                recipient = future_map[
                    future
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
                            ) + "\n"
                        )

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
                                    (
                                        "Gmail authentication "
                                        "failed. Check the "
                                        "Gmail address and "
                                        "App Password."
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
                        ) + "\n"
                    )

                except (
                    smtplib.SMTPConnectError,
                    smtplib.SMTPServerDisconnected,
                    TimeoutError,
                    ConnectionError,
                ) as exc:

                    failed_count += 1

                    error_text = (
                        str(exc).strip()
                        or
                        "SMTP connection error."
                    )

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
                                    error_text[:250],
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
                        ) + "\n"
                    )

                except smtplib.SMTPException as exc:

                    failed_count += 1

                    error_text = (
                        str(exc).strip()
                        or
                        "SMTP error."
                    )

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
                                    error_text[:250],
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
                        ) + "\n"
                    )

                except Exception as exc:

                    failed_count += 1

                    error_text = (
                        str(exc).strip()
                        or
                        "Unknown error."
                    )

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
                                    error_text[:250],
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
                        ) + "\n"
                    )

        finally:

            executor.shutdown(
                wait=True
            )


        # =================================================
        # COMPLETE
        # =================================================

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
            ) + "\n"
        )


    # =====================================================
    # STREAMING RESPONSE
    # =====================================================

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

    response.headers["X-Content-Type-Options"] = (
        "nosniff"
    )

    return response


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "ok",
        "service": "Secure Mail Console",
        "mailer": "Gmail SMTP",
        "parallel_sends":
            MAX_PARALLEL_SENDS,
        "send_delay":
            SEND_DELAY_SECONDS,
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

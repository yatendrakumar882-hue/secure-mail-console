from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    Response,
    stream_with_context
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
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent


# =========================================================
# FLASK APP
# =========================================================

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static"
)

# Explicit WSGI handler
handler = app


# =========================================================
# SECURITY / CONFIG
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


# SESSION_SECRET must exist.
if not SESSION_SECRET:
    raise RuntimeError(
        "SESSION_SECRET is not configured in Vercel."
    )


app.secret_key = SESSION_SECRET


# =========================================================
# SESSION SECURITY
# =========================================================

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600
)


# =========================================================
# MAIL SETTINGS
# =========================================================

MAX_RECIPIENTS = 25

# Exactly 2 simultaneous SMTP sends.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

# SMTP timeout
SMTP_TIMEOUT = 20

# ---------------------------------------------------------
# Slightly slower sending.
#
# Two emails can still be sent simultaneously.
# Each individual worker waits this amount before sending.
# ---------------------------------------------------------

SEND_DELAY_SECONDS = 1.2


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
# AUTHENTICATION
# =========================================================

def authenticated():
    return (
        session.get("authenticated") is True
    )


# =========================================================
# GLOBAL LOGIN PROTECTION
# =========================================================
#
# IMPORTANT:
# This protects the application globally.
#
# Without a valid session:
#   /
#   /send-batch
#   other protected routes
#
# cannot be opened directly.
#
# Login, static files and health remain public.
# =========================================================

@app.before_request
def require_login():

    endpoint = request.endpoint

    # Public routes
    if endpoint in {
        "login",
        "health",
        "static"
    }:
        return None

    # Already authenticated
    if authenticated():
        return None

    # API / sending request
    if (
        request.path.startswith("/api/")
        or request.path == "/send-batch"
    ):
        return jsonify({
            "success": False,
            "message": "Authentication required.",
            "login_required": True
        }), 401

    # Everything else -> login
    return redirect(
        url_for("login")
    )


# =========================================================
# SAFE HEADER CLEANING
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
        text
    )


# =========================================================
# TURNSTILE
# =========================================================

def verify_turnstile(
    token,
    remote_ip=None
):

    if not TURNSTILE_SECRET_KEY:
        return (
            False,
            "TURNSTILE_SECRET_KEY is not configured."
        )

    if not token:
        return (
            False,
            "Cloudflare verification is required."
        )

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token
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
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=10
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        return (
            False,
            "Cloudflare verification failed."
        )

    except Exception:

        return (
            False,
            "Unable to verify Cloudflare."
        )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    # If already logged in, don't show login again.
    if authenticated():
        return redirect(
            url_for("home")
        )

    # -----------------------------------------------------
    # GET
    # -----------------------------------------------------

    if request.method == "GET":

        return render_template(
            "login.html",
            error=None,
            turnstile_site_key=TURNSTILE_SITE_KEY
        )

    # -----------------------------------------------------
    # POST
    # -----------------------------------------------------

    password = str(
        request.form.get(
            "password",
            ""
        )
    )

    # NEVER allow empty environment password.
    if not LOGIN_PASSWORD:

        return render_template(
            "login.html",
            error=(
                "LOGIN_PASSWORD is not configured "
                "in Vercel."
            ),
            turnstile_site_key=TURNSTILE_SITE_KEY
        ), 500

    # Secure constant-time comparison.
    if not secrets.compare_digest(
        password,
        LOGIN_PASSWORD
    ):

        return render_template(
            "login.html",
            error="Incorrect password.",
            turnstile_site_key=TURNSTILE_SITE_KEY
        ), 401

    # -----------------------------------------------------
    # Successful login
    # -----------------------------------------------------

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
    methods=["GET", "POST"]
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

    # Defense-in-depth.
    if not authenticated():

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY
    )


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
    recipient
):

    """
    Sends one email using its own SMTP connection.

    MAX_PARALLEL_SENDS = 2 means at most two of these
    operations run simultaneously.

    A small delay is applied before each individual send
    to make the sending pace slightly slower.
    """

    # -----------------------------------------------------
    # Slight sending delay
    # -----------------------------------------------------

    time.sleep(
        SEND_DELAY_SECONDS
    )

    context = ssl.create_default_context()

    # Generate recipient-specific content.
    final_subject = expand_spintax(
        subject
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
        "utf-8"
    )

    # -----------------------------------------------------
    # Safe headers
    # -----------------------------------------------------

    message["Subject"] = clean_header(
        final_subject
    )

    message["From"] = formataddr(
        (
            clean_header(sender_name),
            gmail
        )
    )

    message["To"] = clean_header(
        recipient
    )

    message["Date"] = formatdate(
        localtime=True
    )

    message["Message-ID"] = make_msgid()

    message["MIME-Version"] = "1.0"

    # -----------------------------------------------------
    # SMTP
    # -----------------------------------------------------

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT
    ) as server:

        server.login(
            gmail,
            app_password
        )

        server.sendmail(
            gmail,
            [recipient],
            message.as_string()
        )

    return {
        "email": recipient,
        "result": "sent"
    }


# =========================================================
# SEND BATCH
# =========================================================

@app.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    # -----------------------------------------------------
    # Defense-in-depth authentication
    # -----------------------------------------------------

    if not authenticated():

        return jsonify({
            "success": False,
            "message": "Authentication required.",
            "login_required": True
        }), 401


    # -----------------------------------------------------
    # JSON
    # -----------------------------------------------------

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
            ""
        )
    )

    gmail = clean_header(
        data.get(
            "gmail",
            ""
        )
    )

    app_password = str(
        data.get(
            "app_password",
            ""
        )
    ).strip()

    subject = clean_header(
        data.get(
            "subject",
            ""
        )
    )

    body = str(
        data.get(
            "body",
            ""
        )
    )

    is_html = bool(
        data.get(
            "is_html",
            False
        )
    )

    recipients = data.get(
        "recipients",
        []
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()


    # =====================================================
    # VALIDATION
    # =====================================================

    if not sender_name:

        return jsonify({
            "success": False,
            "message": "Sender Name is required."
        }), 400


    if not valid_email(gmail):

        return jsonify({
            "success": False,
            "message":
                "Enter a valid Gmail address."
        }), 400


    if not app_password:

        return jsonify({
            "success": False,
            "message":
                "Google App Password is required."
        }), 400


    if not subject:

        return jsonify({
            "success": False,
            "message":
                "Email subject is required."
        }), 400


    if not body.strip():

        return jsonify({
            "success": False,
            "message":
                "Message body is required."
        }), 400


    if not isinstance(
        recipients,
        list
    ):

        return jsonify({
            "success": False,
            "message":
                "Invalid recipient list."
        }), 400


    # =====================================================
    # CLEAN + DEDUPLICATE RECIPIENTS
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
                "No valid recipients found."
        }), 400


    # =====================================================
    # TURNSTILE
    # =====================================================

    verified, verify_error = verify_turnstile(
        turnstile_token,
        request.headers.get(
            "X-Forwarded-For",
            request.remote_addr
        )
    )


    if not verified:

        return jsonify({
            "success": False,
            "message": verify_error
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
        # Initial event
        # -------------------------------------------------

        yield (
            json.dumps(
                {
                    "type": "start",
                    "total": total,
                    "sent": 0,
                    "failed": 0,
                    "remaining": total
                },
                ensure_ascii=False
            ) + "\n"
        )


        # =================================================
        # EXACTLY TWO CONCURRENT SEND WORKERS
        # =================================================

        executor = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        )

        future_map = {}


        try:

            # -------------------------------------------------
            # Submit all jobs.
            #
            # ThreadPoolExecutor ensures only 2 execute
            # simultaneously.
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
                    recipient
                )

                future_map[
                    future
                ] = recipient


            # -------------------------------------------------
            # Process each completed email immediately.
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

                        # -------------------------------------
                        # IMPORTANT:
                        # This event is yielded immediately
                        # after this individual email finishes.
                        # -------------------------------------

                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "email": recipient,
                                    "result": "sent",
                                    "total": total,
                                    "sent": sent_count,
                                    "failed": failed_count,
                                    "remaining":
                                        total -
                                        sent_count -
                                        failed_count
                                },
                                ensure_ascii=False
                            ) + "\n"
                        )

                except smtplib.SMTPAuthenticationError:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type": "progress",
                                "email": recipient,
                                "result": "failed",
                                "error":
                                    "Gmail authentication failed. Check Gmail address and App Password.",
                                "total": total,
                                "sent": sent_count,
                                "failed": failed_count,
                                "remaining":
                                    total -
                                    sent_count -
                                    failed_count
                            },
                            ensure_ascii=False
                        ) + "\n"
                    )

                except (
                    smtplib.SMTPConnectError,
                    smtplib.SMTPServerDisconnected,
                    TimeoutError,
                    ConnectionError
                ) as exc:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type": "progress",
                                "email": recipient,
                                "result": "failed",
                                "error":
                                    f"SMTP connection error: {str(exc)[:250]}",
                                "total": total,
                                "sent": sent_count,
                                "failed": failed_count,
                                "remaining":
                                    total -
                                    sent_count -
                                    failed_count
                            },
                            ensure_ascii=False
                        ) + "\n"
                    )

                except smtplib.SMTPException as exc:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type": "progress",
                                "email": recipient,
                                "result": "failed",
                                "error":
                                    f"SMTP error: {str(exc)[:250]}",
                                "total": total,
                                "sent": sent_count,
                                "failed": failed_count,
                                "remaining":
                                    total -
                                    sent_count -
                                    failed_count
                            },
                            ensure_ascii=False
                        ) + "\n"
                    )

                except Exception as exc:

                    failed_count += 1

                    yield (
                        json.dumps(
                            {
                                "type": "progress",
                                "email": recipient,
                                "result": "failed",
                                "error":
                                    str(exc)[:250]
                                    or "Unknown error.",
                                "total": total,
                                "sent": sent_count,
                                "failed": failed_count,
                                "remaining":
                                    total -
                                    sent_count -
                                    failed_count
                            },
                            ensure_ascii=False
                        ) + "\n"
                    )


        finally:

            executor.shutdown(
                wait=True
            )


        # =================================================
        # FINAL EVENT
        # =================================================

        yield (
            json.dumps(
                {
                    "type": "complete",
                    "success": True,
                    "message": "Sending completed.",
                    "total": total,
                    "sent": sent_count,
                    "failed": failed_count,
                    "remaining":
                        total -
                        sent_count -
                        failed_count
                },
                ensure_ascii=False
            ) + "\n"
        )


    # =====================================================
    # STREAM RESPONSE
    # =====================================================

    response = Response(
        generate(),
        content_type=(
            "application/x-ndjson; charset=utf-8"
        )
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
        "spintax": "always_on",
        "parallel_sends":
            MAX_PARALLEL_SENDS,
        "send_delay":
            SEND_DELAY_SECONDS,
        "authenticated":
            authenticated()
    })


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )

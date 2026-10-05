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

from concurrent.futures import ThreadPoolExecutor, as_completed

from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path


# =========================================================
# PATHS
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


# =========================================================
# FLASK APP
# =========================================================
#
# IMPORTANT:
# This keeps your original working project structure.
#
# Project should be:
#
# project/
# ├── api/
# │   └── index.py
# │
# ├── templates/
# │   ├── index.html
# │   └── login.html
# │
# ├── static/
# │   └── style.css
# │
# ├── requirements.txt
# └── vercel.json
#
# =========================================================

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
    static_url_path="/static"
)


# Explicit Vercel WSGI handler.
handler = app


# =========================================================
# SECURITY / CONFIG
# =========================================================

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    ""
)

MAX_RECIPIENTS = 25

# Exactly two simultaneous workers.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

SMTP_TIMEOUT = 20

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    ""
)

TURNSTILE_SITE_KEY = os.environ.get(
    "TURNSTILE_SITE_KEY",
    ""
)

LOGIN_PASSWORD = os.environ.get(
    "LOGIN_PASSWORD",
    ""
)


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(value):
    return bool(
        EMAIL_RE.fullmatch(
            str(value).strip()
        )
    )


# =========================================================
# AUTHENTICATION
# =========================================================

def authenticated():
    return (
        session.get(
            "authenticated"
        ) is True
    )


# =========================================================
# SAFE HEADER CLEANING
# =========================================================

def clean_header(value):
    """
    Prevent CR/LF header injection.
    """

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
    """
    Example:

    Hello {friend|customer|there}

    One valid option is selected.
    """

    if not text:
        return ""

    def replace_match(match):

        options = [
            option.strip()
            for option in match.group(1).split("|")
            if option.strip()
        ]

        if len(options) < 2:
            return match.group(0)

        return random.choice(
            options
        )

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
    """
    Verify Cloudflare Turnstile.

    Turnstile must be configured in Vercel
    when protection is enabled.
    """

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
        "secret":
            TURNSTILE_SECRET_KEY,

        "response":
            token
    }

    if remote_ip:

        payload["remoteip"] = (
            remote_ip
        )

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
                response.read().decode(
                    "utf-8"
                )
            )

        if result.get(
            "success"
        ) is True:

            return (
                True,
                None
            )

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

    if authenticated():

        return redirect(
            url_for("home")
        )

    error = None

    if request.method == "POST":

        password = str(
            request.form.get(
                "password",
                ""
            )
        )

        configured_password = (
            LOGIN_PASSWORD
        )

        if not configured_password:

            error = (
                "LOGIN_PASSWORD is not configured."
            )

        elif secrets.compare_digest(
            password,
            configured_password
        ):

            session["authenticated"] = True

            return redirect(
                url_for("home")
            )

        else:

            error = (
                "Incorrect password."
            )

    return render_template(
        "login.html",
        error=error
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
        turnstile_site_key=(
            TURNSTILE_SITE_KEY
        )
    )


# =========================================================
# BUILD EMAIL
# =========================================================

def build_email(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient
):
    """
    Build a normal MIME email.

    No fake headers or misleading
    delivery information are added.
    """

    final_subject = (
        expand_spintax(
            subject
        )
    )

    final_body = (
        expand_spintax(
            body
        )
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

    message["Subject"] = (
        final_subject
    )

    message["From"] = formataddr(
        (
            sender_name,
            gmail
        )
    )

    message["To"] = (
        recipient
    )

    message["Date"] = (
        formatdate(
            localtime=True
        )
    )

    message["Message-ID"] = (
        make_msgid()
    )

    message["MIME-Version"] = (
        "1.0"
    )

    return message


# =========================================================
# SMTP WORKER
# =========================================================

def smtp_worker(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipients
):
    """
    One worker owns one SMTP connection.

    This is faster than opening and authenticating
    Gmail separately for every single recipient.
    """

    sent = []
    failed = []

    context = (
        ssl.create_default_context()
    )

    server = None

    try:

        # -------------------------------------------------
        # CONNECT ONCE
        # -------------------------------------------------

        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=SMTP_TIMEOUT
        )

        # -------------------------------------------------
        # LOGIN ONCE
        # -------------------------------------------------

        server.login(
            gmail,
            app_password
        )


        # -------------------------------------------------
        # SEND RECIPIENTS
        # -------------------------------------------------

        for recipient in recipients:

            try:

                message = build_email(
                    gmail,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient
                )

                server.sendmail(
                    gmail,
                    [recipient],
                    message.as_string()
                )

                sent.append(
                    recipient
                )

            except Exception as exc:

                failed.append({
                    "email":
                        recipient,

                    "error":
                        str(exc)
                })


    except smtplib.SMTPAuthenticationError as exc:

        # If authentication itself fails,
        # all recipients assigned to this
        # worker are failed.

        for recipient in recipients:

            failed.append({
                "email":
                    recipient,

                "error":
                    "Gmail authentication failed. "
                    "Check Gmail and App Password."
            })


    except Exception as exc:

        for recipient in recipients:

            failed.append({
                "email":
                    recipient,

                "error":
                    str(exc)
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


    return {
        "sent": sent,
        "failed": failed
    }


# =========================================================
# SPLIT RECIPIENTS
# =========================================================

def split_recipients(
    recipients,
    workers
):
    """
    Split recipients into balanced chunks.

    Example:

    25 recipients
    2 workers

    -> 13 + 12
    """

    chunks = [
        []
        for _ in range(
            workers
        )
    ]

    for index, recipient in enumerate(
        recipients
    ):

        chunks[
            index % workers
        ].append(
            recipient
        )

    return [
        chunk
        for chunk in chunks
        if chunk
    ]


# =========================================================
# SEND BATCH
# =========================================================

@app.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    # -----------------------------------------------------
    # AUTH
    # -----------------------------------------------------

    if not authenticated():

        return jsonify({
            "success":
                False,

            "message":
                "Authentication required."
        }), 401


    # -----------------------------------------------------
    # READ JSON
    # -----------------------------------------------------

    data = request.get_json(
        silent=True
    ) or {}


    # -----------------------------------------------------
    # INPUTS
    # -----------------------------------------------------

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
    ).lower()

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
            "success":
                False,

            "message":
                "Sender Name is required."
        }), 400


    if not valid_email(gmail):

        return jsonify({
            "success":
                False,

            "message":
                "Enter a valid Gmail address."
        }), 400


    if not app_password:

        return jsonify({
            "success":
                False,

            "message":
                "Google App Password is required."
        }), 400


    if not subject:

        return jsonify({
            "success":
                False,

            "message":
                "Email subject is required."
        }), 400


    if not body.strip():

        return jsonify({
            "success":
                False,

            "message":
                "Message body is required."
        }), 400


    if not isinstance(
        recipients,
        list
    ):

        return jsonify({
            "success":
                False,

            "message":
                "Invalid recipient list."
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

        if not valid_email(
            email
        ):
            continue

        if email in seen:
            continue

        seen.add(
            email
        )

        clean_recipients.append(
            email
        )

        if len(
            clean_recipients
        ) >= MAX_RECIPIENTS:

            break


    if not clean_recipients:

        return jsonify({
            "success":
                False,

            "message":
                "No valid recipients found."
        }), 400


    # =====================================================
    # TURNSTILE
    # =====================================================

    remote_ip = (
        request.headers.get(
            "CF-Connecting-IP"
        )
        or request.headers.get(
            "X-Forwarded-For",
            ""
        ).split(",")[0].strip()
        or request.remote_addr
    )


    verified, verify_error = (
        verify_turnstile(
            turnstile_token,
            remote_ip
        )
    )


    if not verified:

        return jsonify({
            "success":
                False,

            "message":
                verify_error
        }), 403


    # =====================================================
    # STREAMING
    # =====================================================

    @stream_with_context
    def generate():

        total = len(
            clean_recipients
        )

        sent_count = 0
        failed_count = 0


        # -------------------------------------------------
        # START
        # -------------------------------------------------

        yield (
            json.dumps({
                "type":
                    "start",

                "total":
                    total,

                "sent":
                    0,

                "failed":
                    0,

                "remaining":
                    total
            }) + "\n"
        )


        # -------------------------------------------------
        # SPLIT INTO 2 WORKERS
        # -------------------------------------------------

        chunks = split_recipients(
            clean_recipients,
            MAX_PARALLEL_SENDS
        )


        executor = (
            ThreadPoolExecutor(
                max_workers=
                    MAX_PARALLEL_SENDS
            )
        )


        futures = {}


        try:

            # ---------------------------------------------
            # START WORKERS
            # ---------------------------------------------

            for chunk in chunks:

                future = executor.submit(
                    smtp_worker,

                    gmail,
                    app_password,

                    sender_name,
                    subject,
                    body,
                    is_html,

                    chunk
                )

                futures[
                    future
                ] = chunk


            # ---------------------------------------------
            # PROCESS WORKER RESULTS
            # ---------------------------------------------

            for future in as_completed(
                futures
            ):

                try:

                    result = (
                        future.result()
                    )


                    # -------------------------------------
                    # SENT
                    # -------------------------------------

                    for email in result[
                        "sent"
                    ]:

                        sent_count += 1

                        yield (
                            json.dumps({
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
                                    total -
                                    sent_count -
                                    failed_count
                            }) + "\n"
                        )


                    # -------------------------------------
                    # FAILED
                    # -------------------------------------

                    for failure in result[
                        "failed"
                    ]:

                        failed_count += 1

                        yield (
                            json.dumps({
                                "type":
                                    "progress",

                                "email":
                                    failure[
                                        "email"
                                    ],

                                "result":
                                    "failed",

                                "error":
                                    failure[
                                        "error"
                                    ],

                                "total":
                                    total,

                                "sent":
                                    sent_count,

                                "failed":
                                    failed_count,

                                "remaining":
                                    total -
                                    sent_count -
                                    failed_count
                            }) + "\n"
                        )


                except Exception as exc:

                    # ---------------------------------
                    # Worker-level failure
                    # ---------------------------------

                    chunk = futures[
                        future
                    ]

                    for email in chunk:

                        failed_count += 1

                        yield (
                            json.dumps({
                                "type":
                                    "progress",

                                "email":
                                    email,

                                "result":
                                    "failed",

                                "error":
                                    str(exc),

                                "total":
                                    total,

                                "sent":
                                    sent_count,

                                "failed":
                                    failed_count,

                                "remaining":
                                    total -
                                    sent_count -
                                    failed_count
                            }) + "\n"
                        )


        finally:

            executor.shutdown(
                wait=True
            )


        # =================================================
        # COMPLETE
        # =================================================

        yield (
            json.dumps({
                "type":
                    "complete",

                "success":
                    True,

                "message":
                    "Sending complete.",

                "total":
                    total,

                "sent":
                    sent_count,

                "failed":
                    failed_count,

                "remaining":
                    0
            }) + "\n"
        )


    # =====================================================
    # RESPONSE
    # =====================================================

    response = Response(
        generate(),
        content_type=(
            "application/x-ndjson; "
            "charset=utf-8"
        )
    )


    response.headers[
        "Cache-Control"
    ] = (
        "no-cache, "
        "no-store, "
        "must-revalidate"
    )


    response.headers[
        "Pragma"
    ] = "no-cache"


    response.headers[
        "X-Accel-Buffering"
    ] = "no"


    return response


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():

    return jsonify({
        "status":
            "ok",

        "service":
            "Secure Mail Console",

        "mailer":
            "Gmail SMTP",

        "parallel_sends":
            MAX_PARALLEL_SENDS,

        "max_recipients":
            MAX_RECIPIENTS,

        "spintax":
            "enabled"
    })


# =========================================================
# BASIC ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def page_not_found(error):

    return jsonify({
        "success":
            False,

        "message":
            "Page not found."
    }), 404


# =========================================================
# LOCAL DEVELOPMENT ONLY
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                "5000"
            )
        ),
        debug=False
    )

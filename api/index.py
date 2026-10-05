import os
import re
import json
import ssl
import smtplib
import secrets
import hashlib
import random
import string
import urllib.parse
import urllib.request

from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template,
    session,
    jsonify,
    Response,
    stream_with_context,
)


# =========================================================
# PATHS
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# =========================================================
# FLASK APP
# =========================================================
#
# Your project has index.html, login.html and style.css
# in the project root.
#
# Therefore:
# templates -> BASE_DIR
# static    -> BASE_DIR
#
# This allows:
# {{ url_for('static', filename='style.css') }}
# to correctly load /static/style.css
# =========================================================

app = Flask(
    __name__,
    template_folder=BASE_DIR,
    static_folder=BASE_DIR,
    static_url_path="/static",
)


# Vercel WSGI entry point
handler = app


# =========================================================
# CONFIG
# =========================================================

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    secrets.token_hex(32)
)

MAX_RECIPIENTS = 25

# Two emails can be processed at the same time.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

LOGIN_PASSWORD = os.environ.get(
    "LOGIN_PASSWORD",
    ""
)

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    ""
)

TURNSTILE_SITE_KEY = os.environ.get(
    "TURNSTILE_SITE_KEY",
    ""
)


# =========================================================
# HELPERS
# =========================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def is_valid_email(email):
    return bool(
        EMAIL_RE.match(
            email.strip()
        )
    )


def clean_recipients(recipients):
    """
    Clean, normalize and deduplicate recipients.
    Maximum 25 recipients.
    """

    if not isinstance(
        recipients,
        list
    ):
        return []

    cleaned = []

    seen = set()

    for item in recipients:

        if not isinstance(
            item,
            str
        ):
            continue

        email = item.strip().lower()

        if not email:
            continue

        if not is_valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)
        cleaned.append(email)

        if len(cleaned) >= MAX_RECIPIENTS:
            break

    return cleaned


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

    becomes one of:
    Hello friend
    Hello customer
    Hello there
    """

    if not text:
        return ""

    def replace(match):
        choices = match.group(1).split("|")

        if not choices:
            return match.group(0)

        return random.choice(
            choices
        ).strip()

    previous = None
    current = text

    # Handle nested/simple spintax safely.
    for _ in range(10):

        if current == previous:
            break

        previous = current

        current = SPINTAX_RE.sub(
            replace,
            current
        )

    return current


# =========================================================
# TURNSTILE
# =========================================================

def verify_turnstile(token, remote_ip=None):
    """
    Verify Cloudflare Turnstile.

    If TURNSTILE_SECRET_KEY is not configured,
    verification is skipped so the application
    can still run.
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

    try:

        data = urllib.parse.urlencode(
            payload
        ).encode("utf-8")

        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            headers={
                "Content-Type":
                    "application/x-www-form-urlencoded"
            },
            method="POST",
        )

        with urllib.request.urlopen(
            req,
            timeout=8
        ) as response:

            result = json.loads(
                response.read().decode(
                    "utf-8"
                )
            )

        return bool(
            result.get("success")
        )

    except Exception:
        return False


# =========================================================
# LOGIN
# =========================================================

def is_logged_in():
    return bool(
        session.get("logged_in")
    )


@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if is_logged_in():
        return redirect(
            url_for("index")
        )

    error = None

    if request.method == "POST":

        password = (
            request.form.get(
                "password",
                ""
            )
            .strip()
        )

        configured_password = (
            LOGIN_PASSWORD
        )

        if (
            configured_password
            and secrets.compare_digest(
                password,
                configured_password
            )
        ):

            session["logged_in"] = True

            return redirect(
                url_for("index")
            )

        error = "Invalid password."

    return render_template(
        "login.html",
        error=error
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# MAIN PAGE
# =========================================================

@app.route("/")
def index():

    if not is_logged_in():
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
    recipient,
    subject,
    body,
    is_html
):
    """
    Opens one authenticated Gmail SMTP connection,
    sends one message, then closes the connection.

    Two calls to this function are allowed to run
    simultaneously.
    """

    ssl_context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=ssl_context,
        timeout=30
    ) as server:

        server.login(
            gmail,
            app_password
        )

        final_subject = expand_spintax(
            subject
        )

        final_body = expand_spintax(
            body
        )

        if is_html:
            message = MIMEText(
                final_body,
                "html",
                "utf-8"
            )
        else:
            message = MIMEText(
                final_body,
                "plain",
                "utf-8"
            )

        message["From"] = (
            f"{sender_name} <{gmail}>"
        )

        message["To"] = recipient

        message["Subject"] = (
            final_subject
        )

        message["Date"] = formatdate(
            localtime=True
        )

        message["Message-ID"] = (
            make_msgid()
        )

        message["MIME-Version"] = (
            "1.0"
        )

        server.sendmail(
            gmail,
            [recipient],
            message.as_string()
        )

    return True


# =========================================================
# SEND BATCH
# =========================================================

@app.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    if not is_logged_in():

        return jsonify({
            "message":
                "Authentication required."
        }), 401


    # -----------------------------------------------------
    # JSON
    # -----------------------------------------------------

    try:
        data = request.get_json(
            silent=True
        ) or {}

    except Exception:
        data = {}


    sender_name = str(
        data.get(
            "sender_name",
            ""
        )
    ).strip()


    gmail = str(
        data.get(
            "gmail",
            ""
        )
    ).strip().lower()


    app_password = str(
        data.get(
            "app_password",
            ""
        )
    ).strip()


    subject = str(
        data.get(
            "subject",
            ""
        )
    ).strip()


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


    recipients = clean_recipients(
        data.get(
            "recipients",
            []
        )
    )


    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()


    # -----------------------------------------------------
    # VALIDATION
    # -----------------------------------------------------

    if not sender_name:

        return jsonify({
            "message":
                "Sender name is required."
        }), 400


    if not is_valid_email(gmail):

        return jsonify({
            "message":
                "Enter a valid Gmail address."
        }), 400


    if not app_password:

        return jsonify({
            "message":
                "Google App Password is required."
        }), 400


    if not subject:

        return jsonify({
            "message":
                "Email subject is required."
        }), 400


    if not body.strip():

        return jsonify({
            "message":
                "Message body is required."
        }), 400


    if not recipients:

        return jsonify({
            "message":
                "No valid recipients found."
        }), 400


    # -----------------------------------------------------
    # TURNSTILE
    # -----------------------------------------------------

    remote_ip = (
        request.headers.get(
            "CF-Connecting-IP"
        )
        or request.remote_addr
    )


    if not verify_turnstile(
        turnstile_token,
        remote_ip
    ):

        return jsonify({
            "message":
                "Cloudflare verification failed."
        }), 403


    # -----------------------------------------------------
    # COUNTERS
    # -----------------------------------------------------

    total = len(
        recipients
    )

    sent = 0
    failed = 0

    results = []


    # -----------------------------------------------------
    # STREAM GENERATOR
    # -----------------------------------------------------

    @stream_with_context
    def generate():

        nonlocal sent
        nonlocal failed


        # ---------------------------------------------
        # START EVENT
        # ---------------------------------------------

        yield json.dumps({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total
        }) + "\n"


        # ---------------------------------------------
        # TWO PARALLEL WORKERS
        # ---------------------------------------------

        executor = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        )


        futures = {}

        try:

            for recipient in recipients:

                future = executor.submit(
                    send_one_email,
                    gmail,
                    app_password,
                    sender_name,
                    recipient,
                    subject,
                    body,
                    is_html
                )

                futures[future] = (
                    recipient
                )


            # -----------------------------------------
            # PROCESS RESULTS AS THEY FINISH
            # -----------------------------------------

            for future in as_completed(
                futures
            ):

                recipient = futures[
                    future
                ]

                try:

                    future.result()

                    sent += 1

                    results.append({
                        "recipient":
                            recipient,
                        "status":
                            "sent"
                    })

                except Exception as exc:

                    failed += 1

                    results.append({
                        "recipient":
                            recipient,
                        "status":
                            "failed",
                        "error":
                            str(exc)
                    })


                remaining = (
                    total
                    - sent
                    - failed
                )


                # -------------------------------------
                # PROGRESS EVENT
                # -------------------------------------

                yield json.dumps({
                    "type":
                        "progress",

                    "total":
                        total,

                    "sent":
                        sent,

                    "failed":
                        failed,

                    "remaining":
                        remaining,

                    "recipient":
                        recipient
                }) + "\n"


        finally:

            executor.shutdown(
                wait=True,
                cancel_futures=False
            )


        # ---------------------------------------------
        # COMPLETE
        # ---------------------------------------------

        yield json.dumps({
            "type":
                "complete",

            "total":
                total,

            "sent":
                sent,

            "failed":
                failed,

            "remaining":
                0,

            "message":
                "Sending complete."
        }) + "\n"


    # =====================================================
    # RESPONSE
    # =====================================================

    response = Response(
        generate(),
        mimetype=(
            "application/x-ndjson"
        )
    )


    response.headers[
        "Cache-Control"
    ] = "no-cache, no-store, must-revalidate"


    response.headers[
        "Pragma"
    ] = "no-cache"


    response.headers[
        "X-Accel-Buffering"
    ] = "no"


    return response


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health")
def health():

    return jsonify({
        "status":
            "ok",

        "service":
            "secure-mail-console",

        "parallel_sends":
            MAX_PARALLEL_SENDS
    })


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "message":
            "Page not found."
    }), 404


@app.errorhandler(500)
def internal_error(error):

    # Do not expose internal traceback
    # to the browser.

    return jsonify({
        "message":
            "Internal server error."
    }), 500


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "5000"
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )

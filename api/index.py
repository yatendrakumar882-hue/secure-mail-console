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
import hmac
import json
import os
import re
import ssl
import smtplib
import time
import urllib.parse
import urllib.request
from pathlib import Path

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid


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
# VERCEL ENV
# ============================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is not configured.")

if not LOGIN_PASSWORD:
    raise RuntimeError("LOGIN_PASSWORD is not configured.")

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)


# ============================================================
# SETTINGS
# ============================================================

MAX_RECIPIENTS = 25

# Strictly one-by-one.
MAX_PARALLEL_SENDS = 1

# Delay between messages.
SEND_DELAY_SECONDS = 1.0

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_EMAIL_LENGTH = 254
MAX_SUBJECT_LENGTH = 998
MAX_SENDER_NAME_LENGTH = 200
MAX_BODY_LENGTH = 100_000


# ============================================================
# EMAIL VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def normalize_email(value):
    return str(value or "").strip().lower()


def valid_email(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    if not value:
        return False

    if len(value) > MAX_EMAIL_LENGTH:
        return False

    return bool(EMAIL_RE.fullmatch(value))


def clean_header(value, max_length):
    value = str(value or "")

    # Prevent header injection.
    value = value.replace("\r", " ")
    value = value.replace("\n", " ")

    return value.strip()[:max_length]


def safe_error(exc):
    message = str(exc or "").strip()

    if not message:
        return "Unknown sending error."

    return message[:300]


def ndjson(payload):
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )


# ============================================================
# HTML -> TEXT
# ============================================================

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


# ============================================================
# MESSAGE
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

    sender_name = clean_header(
        sender_name,
        MAX_SENDER_NAME_LENGTH,
    )

    subject = clean_header(
        subject,
        MAX_SUBJECT_LENGTH,
    )

    recipient = clean_header(
        recipient,
        MAX_EMAIL_LENGTH,
    )

    if is_html:

        message = MIMEMultipart("alternative")

        plain_body = html_to_plain_text(body)

        if not plain_body:
            plain_body = "This message contains HTML content."

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

    message["Subject"] = subject

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


# ============================================================
# SMTP
# ============================================================

def open_smtp(gmail, app_password):

    context = ssl.create_default_context()

    server = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT,
    )

    try:

        server.ehlo()

        server.login(
            gmail,
            app_password,
        )

        return server

    except Exception:

        try:
            server.quit()
        except Exception:
            pass

        raise


def send_one(
    server,
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=subject,
        body=body,
        is_html=is_html,
        recipient=recipient,
    )

    server.sendmail(
        gmail,
        [recipient],
        message.as_string(),
    )


# ============================================================
# TURNSTILE
# ============================================================

def verify_turnstile(token, remote_ip=None):

    # If Turnstile is not configured, don't block the app.
    if not TURNSTILE_SECRET_KEY:
        return True, None

    if not token:
        return False, "Turnstile verification required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        payload
    ).encode("utf-8")

    try:

        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=encoded,
            headers={
                "Content-Type":
                    "application/x-www-form-urlencoded"
            },
            method="POST",
        )

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

        return False, "Turnstile verification failed."

    except Exception as exc:

        return False, safe_error(exc)


# ============================================================
# AUTH
# ============================================================

def is_logged_in():
    return session.get("authenticated") is True


def require_login(view):

    def wrapped(*args, **kwargs):

        if not is_logged_in():

            if request.path.startswith("/api/"):
                return jsonify(
                    {
                        "ok": False,
                        "error": "Authentication required.",
                    }
                ), 401

            return redirect(
                url_for("login")
            )

        return view(*args, **kwargs)

    wrapped.__name__ = view.__name__

    return wrapped


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":

        return render_template(
            "login.html",
            turnstile_site_key=TURNSTILE_SITE_KEY,
        )

    password = request.form.get(
        "password",
        "",
    )

    if not hmac.compare_digest(
        password,
        LOGIN_PASSWORD,
    ):

        return render_template(
            "login.html",
            error="Invalid password.",
            turnstile_site_key=TURNSTILE_SITE_KEY,
        ), 401

    session.clear()

    session["authenticated"] = True

    session.permanent = True

    return redirect(
        url_for("home")
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# HOME
# ============================================================

@app.route("/")
@require_login
def home():

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return jsonify(
        {
            "ok": True,
            "mode": "one-by-one",
            "parallel": 1,
            "max_recipients": MAX_RECIPIENTS,
            "delay": SEND_DELAY_SECONDS,
        }
    )


# ============================================================
# SEND BATCH
# ============================================================

@app.route(
    "/send-batch",
    methods=["POST"],
)
@require_login
def send_batch():

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify(
            {
                "ok": False,
                "error": "Invalid JSON request.",
            }
        ), 400

    sender_name = str(
        data.get("sender_name", "")
    ).strip()

    gmail = normalize_email(
        data.get("gmail", "")
    )

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = str(
        data.get("subject", "")
    ).strip()

    body = str(
        data.get("body", "")
    )

    is_html = bool(
        data.get("is_html", False)
    )

    recipients_input = data.get(
        "recipients",
        [],
    )

    turnstile_token = str(
        data.get("turnstile_token", "")
    ).strip()

    # --------------------------------------------------------
    # GMAIL
    # --------------------------------------------------------

    if not valid_email(gmail):

        return jsonify(
            {
                "ok": False,
                "error": "Valid Gmail address required.",
            }
        ), 400

    if not gmail.endswith("@gmail.com"):

        return jsonify(
            {
                "ok": False,
                "error": "Please use a Gmail address.",
            }
        ), 400

    if not app_password:

        return jsonify(
            {
                "ok": False,
                "error": "Gmail App Password is required.",
            }
        ), 400

    # --------------------------------------------------------
    # SENDER
    # --------------------------------------------------------

    if not sender_name:

        sender_name = gmail.split(
            "@",
            1,
        )[0]

    sender_name = clean_header(
        sender_name,
        MAX_SENDER_NAME_LENGTH,
    )

    # --------------------------------------------------------
    # SUBJECT
    # --------------------------------------------------------

    subject = clean_header(
        subject,
        MAX_SUBJECT_LENGTH,
    )

    if not subject:

        return jsonify(
            {
                "ok": False,
                "error": "Subject is required.",
            }
        ), 400

    # --------------------------------------------------------
    # BODY
    # --------------------------------------------------------

    if not body.strip():

        return jsonify(
            {
                "ok": False,
                "error": "Email body is required.",
            }
        ), 400

    if len(body) > MAX_BODY_LENGTH:

        return jsonify(
            {
                "ok": False,
                "error": "Email body is too large.",
            }
        ), 400

    # --------------------------------------------------------
    # RECIPIENTS
    # --------------------------------------------------------

    if isinstance(
        recipients_input,
        str,
    ):

        recipients_input = re.split(
            r"[\s,;]+",
            recipients_input,
        )

    if not isinstance(
        recipients_input,
        list,
    ):

        return jsonify(
            {
                "ok": False,
                "error": "Recipients must be a list.",
            }
        ), 400

    recipients = []

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

        recipients.append(email)

    if invalid:

        return jsonify(
            {
                "ok": False,
                "error": "One or more email addresses are invalid.",
                "invalid": invalid[:10],
            }
        ), 400

    if not recipients:

        return jsonify(
            {
                "ok": False,
                "error": "Add at least one recipient.",
            }
        ), 400

    if len(recipients) > MAX_RECIPIENTS:

        return jsonify(
            {
                "ok": False,
                "error": (
                    f"Maximum {MAX_RECIPIENTS} "
                    "recipients are allowed."
                ),
            }
        ), 400

    # --------------------------------------------------------
    # TURNSTILE
    # --------------------------------------------------------

    verified, error = verify_turnstile(
        turnstile_token,
        request.headers.get(
            "CF-Connecting-IP"
        ) or request.remote_addr,
    )

    if not verified:

        return jsonify(
            {
                "ok": False,
                "error": error
                or "Turnstile verification failed.",
            }
        ), 403

    # --------------------------------------------------------
    # STREAM
    # --------------------------------------------------------

    @stream_with_context
    def generate():

        total = len(recipients)

        sent_count = 0
        failed_count = 0

        server = None

        # Tell frontend sending started.
        yield ndjson(
            {
                "type": "start",
                "ok": True,
                "total": total,
                "status": "sending",
            }
        )

        # ----------------------------------------------------
        # LOGIN SMTP ONCE
        # ----------------------------------------------------

        try:

            server = open_smtp(
                gmail,
                app_password,
            )

        except Exception as exc:

            error_message = safe_error(exc)

            yield ndjson(
                {
                    "type": "error",
                    "ok": False,
                    "stage": "smtp_login",
                    "error": error_message,
                }
            )

            yield ndjson(
                {
                    "type": "complete",
                    "ok": False,
                    "total": total,
                    "sent": 0,
                    "failed": total,
                    "status": "complete",
                }
            )

            return

        # ----------------------------------------------------
        # SEND ONE-BY-ONE
        # ----------------------------------------------------

        try:

            for index, recipient in enumerate(
                recipients,
                start=1,
            ):

                try:

                    send_one(
                        server=server,
                        gmail=gmail,
                        sender_name=sender_name,
                        subject=subject,
                        body=body,
                        is_html=is_html,
                        recipient=recipient,
                    )

                    sent_count += 1

                    yield ndjson(
                        {
                            "type": "progress",
                            "ok": True,
                            "index": index,
                            "total": total,
                            "email": recipient,
                            "status": "sent",
                            "sent": sent_count,
                            "failed": failed_count,
                        }
                    )

                except Exception as exc:

                    failed_count += 1

                    yield ndjson(
                        {
                            "type": "progress",
                            "ok": False,
                            "index": index,
                            "total": total,
                            "email": recipient,
                            "status": "failed",
                            "error": safe_error(exc),
                            "sent": sent_count,
                            "failed": failed_count,
                        }
                    )

                # Don't delay after final recipient.
                if index < total:

                    time.sleep(
                        SEND_DELAY_SECONDS
                    )

        finally:

            if server is not None:

                try:
                    server.quit()

                except Exception:

                    try:
                        server.close()
                    except Exception:
                        pass

        # ----------------------------------------------------
        # COMPLETE
        # ----------------------------------------------------

        yield ndjson(
            {
                "type": "complete",
                "ok": failed_count == 0,
                "total": total,
                "sent": sent_count,
                "failed": failed_count,
                "status": "complete",
            }
        )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    response = Response(
        generate(),
        mimetype="application/x-ndjson",
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate"
    )

    response.headers["Pragma"] = "no-cache"

    response.headers["Expires"] = "0"

    response.headers["X-Accel-Buffering"] = "no"

    response.headers["X-Content-Type-Options"] = "nosniff"

    return response


# ============================================================
# API STATUS
# ============================================================

@app.route("/api/status")
@require_login
def api_status():

    return jsonify(
        {
            "ok": True,
            "sending": False,
            "mode": "one-by-one",
            "parallel": 1,
            "max_recipients": MAX_RECIPIENTS,
        }
    )


# ============================================================
# VERCEL
# ============================================================

handler = app

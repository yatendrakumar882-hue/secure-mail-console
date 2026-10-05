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
# PATHS / APP
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
# VERCEL ENVIRONMENT VARIABLES
# Keep these names unchanged.
# ============================================================

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()


if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is not configured in Vercel.")

if not LOGIN_PASSWORD:
    raise RuntimeError("LOGIN_PASSWORD is not configured in Vercel.")


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

# Strictly one email at a time.
MAX_PARALLEL_SENDS = 1

# Keep this low but non-zero for more controlled sending.
SEND_DELAY_SECONDS = 1.0

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_SENDER_NAME_LENGTH = 200
MAX_EMAIL_LENGTH = 254
MAX_SUBJECT_LENGTH = 998
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


# ============================================================
# SECURITY / HELPERS
# ============================================================

def authenticated():
    return session.get("authenticated") is True


def clean_header(value, max_length=998):
    """
    Prevent CR/LF header injection.
    """
    value = str(value or "")

    value = value.replace("\r", " ")
    value = value.replace("\n", " ")

    value = value.strip()

    return value[:max_length]


def safe_error(exc, fallback="Sending failed"):
    text = str(exc or "").strip()

    if not text:
        return fallback

    return text[:300]


def ndjson(data):
    return json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
    ) + "\n"


# ============================================================
# HTML -> PLAIN TEXT
# ============================================================

def html_to_plain_text(html):
    text = str(html or "")

    # Remove scripts/styles.
    text = re.sub(
        r"<(script|style)\b[^>]*>.*?</\1>",
        "",
        text,
        flags=re.I | re.S,
    )

    # Basic line breaks.
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

    # Remove remaining HTML tags.
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

    # Clean spaces.
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
# SMTP CONNECTION
# ============================================================

def open_smtp_connection(gmail, app_password):
    """
    Open one authenticated Gmail SMTP connection.

    The connection is reused for the complete batch instead
    of opening a new SMTP connection for every recipient.
    """

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


# ============================================================
# SEND ONE EMAIL
# ============================================================

def send_one_email(
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
    """
    Verify Cloudflare Turnstile.

    If Turnstile secret is not configured, this function allows
    the request so the app can still operate.
    """

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

    data = urllib.parse.urlencode(
        payload
    ).encode("utf-8")

    try:
        request_obj = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            method="POST",
        )

        with urllib.request.urlopen(
            request_obj,
            timeout=10,
        ) as response:

            raw = response.read().decode(
                "utf-8",
                errors="replace",
            )

            result = json.loads(raw)

        if result.get("success") is True:
            return True, None

        return False, "Turnstile verification failed."

    except Exception as exc:
        return False, safe_error(
            exc,
            "Turnstile verification unavailable.",
        )


# ============================================================
# LOGIN REQUIRED DECORATOR
# ============================================================

def require_login(view_function):
    def wrapper(*args, **kwargs):
        if not authenticated():
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

        return view_function(
            *args,
            **kwargs,
        )

    wrapper.__name__ = view_function.__name__

    return wrapper


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

    if not secrets_compare(
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
# CONSTANT-TIME PASSWORD COMPARISON
# ============================================================

def secrets_compare(a, b):
    import hmac

    return hmac.compare_digest(
        str(a),
        str(b),
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
            "service": "mail-sender",
            "sending_mode": "sequential",
            "max_recipients": MAX_RECIPIENTS,
            "max_parallel_sends": MAX_PARALLEL_SENDS,
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

    # --------------------------------------------------------
    # INPUTS
    # --------------------------------------------------------

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
    # VALIDATE GMAIL
    # --------------------------------------------------------

    if not valid_email(gmail):
        return jsonify(
            {
                "ok": False,
                "error": "Please enter a valid Gmail address.",
            }
        ), 400

    if not gmail.endswith("@gmail.com"):
        return jsonify(
            {
                "ok": False,
                "error": "This version expects a Gmail account.",
            }
        ), 400

    # --------------------------------------------------------
    # APP PASSWORD
    # --------------------------------------------------------

    if not app_password:
        return jsonify(
            {
                "ok": False,
                "error": "Gmail App Password is required.",
            }
        ), 400

    # --------------------------------------------------------
    # SENDER NAME
    # --------------------------------------------------------

    if not sender_name:
        sender_name = gmail.split("@", 1)[0]

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
                "error": "Invalid recipient address.",
                "invalid": invalid[:10],
            }
        ), 400

    if not recipients:
        return jsonify(
            {
                "ok": False,
                "error": "At least one recipient is required.",
            }
        ), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify(
            {
                "ok": False,
                "error": (
                    f"Maximum {MAX_RECIPIENTS} recipients "
                    "are allowed per batch."
                ),
            }
        ), 400

    # --------------------------------------------------------
    # TURNSTILE
    # --------------------------------------------------------

    verified, turnstile_error = verify_turnstile(
        turnstile_token,
        request.headers.get("CF-Connecting-IP")
        or request.remote_addr,
    )

    if not verified:
        return jsonify(
            {
                "ok": False,
                "error": turnstile_error
                or "Turnstile verification failed.",
            }
        ), 403

    # --------------------------------------------------------
    # STREAMING GENERATOR
    # --------------------------------------------------------

    @stream_with_context
    def generate():

        total = len(recipients)

        sent_count = 0
        failed_count = 0

        server = None

        # Initial event.
        yield ndjson(
            {
                "type": "start",
                "ok": True,
                "total": total,
                "mode": "sequential",
                "parallel": 1,
            }
        )

        try:

            # ------------------------------------------------
            # OPEN ONE SMTP CONNECTION
            # ------------------------------------------------

            try:

                server = open_smtp_connection(
                    gmail,
                    app_password,
                )

            except Exception as exc:

                error_message = safe_error(
                    exc,
                    "Could not connect/login to Gmail SMTP.",
                )

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
                    }
                )

                return

            # ------------------------------------------------
            # ONE-BY-ONE SENDING
            # ------------------------------------------------

            for index, recipient in enumerate(
                recipients,
                start=1,
            ):

                try:

                    send_one_email(
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

                    error_message = safe_error(
                        exc,
                        "Email sending failed.",
                    )

                    yield ndjson(
                        {
                            "type": "progress",
                            "ok": False,
                            "index": index,
                            "total": total,
                            "email": recipient,
                            "status": "failed",
                            "error": error_message,
                            "sent": sent_count,
                            "failed": failed_count,
                        }
                    )

                # --------------------------------------------
                # DELAY BETWEEN RECIPIENTS
                # --------------------------------------------

                if index < total:
                    time.sleep(
                        SEND_DELAY_SECONDS
                    )

        finally:

            # ------------------------------------------------
            # CLOSE SMTP
            # ------------------------------------------------

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
            }
        )

    # ========================================================
    # STREAM RESPONSE
    # ========================================================

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

    response.headers["Connection"] = "keep-alive"

    return response


# ============================================================
# OPTIONAL API STATUS
# ============================================================

@app.route("/api/status")
@require_login
def api_status():

    return jsonify(
        {
            "ok": True,
            "authenticated": True,
            "sending_mode": "one-by-one",
            "parallel_sends": 1,
            "max_recipients": MAX_RECIPIENTS,
            "delay_seconds": SEND_DELAY_SECONDS,
        }
    )


# ============================================================
# VERCEL HANDLER
# ============================================================

# Vercel's Python runtime can use the Flask WSGI app directly.
# "handler" is already defined above.

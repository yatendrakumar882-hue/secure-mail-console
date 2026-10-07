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

from pathlib import Path
from queue import Queue
from threading import Thread
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"


# ============================================================
# FLASK APP
# ============================================================

app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
    static_url_path="/static",
)

# Vercel handler
handler = app


# ============================================================
# ENVIRONMENT VARIABLES
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


# ============================================================
# SESSION / SECURITY SETTINGS
# ============================================================

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

# Two SMTP connections / workers.
# This is intentionally conservative for Gmail stability.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# Delay between messages handled by the same worker.
SEND_DELAY_SECONDS = 1.8


# ============================================================
# VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9-]+"
    r"(?:\.[A-Za-z0-9-]+)+$"
)


def is_valid_email(email):
    if not email:
        return False

    email = email.strip()

    if len(email) > 254:
        return False

    return bool(EMAIL_RE.match(email))


def normalize_email(email):
    if not email:
        return ""

    return email.strip().lower()


# ============================================================
# AUTHENTICATION
# ============================================================

def authenticated():
    return session.get("authenticated") is True


@app.before_request
def require_login():
    endpoint = request.endpoint

    allowed_endpoints = {
        "login",
        "health",
        "static",
    }

    if endpoint in allowed_endpoints:
        return None

    if authenticated():
        return None

    # API requests receive JSON instead of redirect.
    if request.path.startswith("/send"):
        return jsonify(
            {
                "error": "Authentication required.",
                "login_required": True,
            }
        ), 401

    return redirect(url_for("login"))


# ============================================================
# HEADER CLEANING
# ============================================================

def clean_header(value):
    """
    Prevent CR/LF header injection.
    """
    if value is None:
        return ""

    return str(value).replace("\r", "").replace("\n", "").strip()


# ============================================================
# PERSONALIZATION
# ============================================================

def get_recipient_name(email):
    """
    Basic name extraction from the email address.

    Example:
        john.smith@example.com
        -> John Smith
    """

    local_part = email.split("@", 1)[0]

    local_part = re.sub(
        r"[._\-+]+",
        " ",
        local_part,
    )

    local_part = re.sub(
        r"\d+",
        "",
        local_part,
    )

    local_part = re.sub(
        r"\s+",
        " ",
        local_part,
    ).strip()

    if not local_part:
        return "there"

    return local_part.title()


def personalize_text(text, recipient):
    """
    Supported placeholders:

    {{name}}
    {{email}}
    {{hi}}
    {{hello}}
    {{thanks}}
    {{ref_code}}
    """

    if text is None:
        return ""

    name = get_recipient_name(recipient)

    first_name = name.split()[0] if name else "there"

    ref_code = secrets.token_hex(4).upper()

    replacements = {
        "{{name}}": name,
        "{{email}}": recipient,
        "{{hi}}": f"Hi {first_name}",
        "{{hello}}": f"Hello {first_name}",
        "{{thanks}}": "Thank you",
        "{{ref_code}}": ref_code,
    }

    result = str(text)

    for key, value in replacements.items():
        result = result.replace(key, value)

    return result


# ============================================================
# HTML -> PLAIN TEXT
# ============================================================

def html_to_plain_text(html):
    if not html:
        return ""

    text = html

    # Common line breaks.
    text = re.sub(
        r"(?i)<br\s*/?>",
        "\n",
        text,
    )

    text = re.sub(
        r"(?i)</p\s*>",
        "\n\n",
        text,
    )

    text = re.sub(
        r"(?i)</div\s*>",
        "\n",
        text,
    )

    text = re.sub(
        r"(?i)</li\s*>",
        "\n",
        text,
    )

    # Remove tags.
    text = re.sub(
        r"<[^>]+>",
        "",
        text,
    )

    # Decode basic entities.
    replacements = {
        "&nbsp;": " ",
        "&amp;": "&",
        "&lt;": "<",
        "&gt;": ">",
        "&quot;": '"',
        "&#39;": "'",
    }

    for key, value in replacements.items():
        text = text.replace(key, value)

    # Normalize whitespace.
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
# TURNSTILE
# ============================================================

def turnstile_enabled():
    """
    Turnstile is enabled only when BOTH keys exist.

    If both env vars are empty, Turnstile is disabled.

    Do not put fake Cloudflare keys here.
    """

    return bool(
        TURNSTILE_SITE_KEY
        and TURNSTILE_SECRET_KEY
    )


def verify_turnstile(token, remote_ip=None):
    """
    Verify Cloudflare Turnstile.

    Returns:
        (True, "")
        or
        (False, "error message")
    """

    if not turnstile_enabled():
        return True, ""

    if not token:
        return False, "Cloudflare verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    request_obj = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Secure-Mail-Console/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request_obj,
            timeout=10,
        ) as response:

            raw = response.read().decode(
                "utf-8",
                errors="replace",
            )

            data = json.loads(raw)

        if data.get("success") is True:
            return True, ""

        return False, "Cloudflare verification failed."

    except Exception:
        return False, "Unable to verify Cloudflare."


# ============================================================
# EMAIL MESSAGE
# ============================================================

def build_message(
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):
    """
    Build standards-compliant MIME email.

    From is always the authenticated Gmail address.
    """

    gmail = clean_header(gmail)
    sender_name = clean_header(sender_name)
    subject = clean_header(subject)
    recipient = clean_header(recipient)

    personalized_body = personalize_text(
        body,
        recipient,
    )

    plain_body = (
        html_to_plain_text(personalized_body)
        if is_html
        else personalized_body
    )

    if is_html:
        message = MIMEMultipart("alternative")

        plain_part = MIMEText(
            plain_body,
            "plain",
            "utf-8",
        )

        html_part = MIMEText(
            personalized_body,
            "html",
            "utf-8",
        )

        message.attach(plain_part)
        message.attach(html_part)

    else:
        message = MIMEText(
            personalized_body,
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
    message["MIME-Version"] = "1.0"

    return message


# ============================================================
# SMTP CONNECTION
# ============================================================

def create_smtp_connection(gmail, app_password):
    """
    Create and authenticate one Gmail SMTP connection.
    """

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

    return server


def close_smtp(server):
    if server is None:
        return

    try:
        server.quit()
    except Exception:
        try:
            server.close()
        except Exception:
            pass


# ============================================================
# SINGLE EMAIL SEND
# ============================================================

def send_with_connection(
    server,
    gmail,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):
    """
    Send one email through an existing authenticated SMTP
    connection.
    """

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
# WORKER
# ============================================================

def smtp_worker(
    worker_id,
    recipients,
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    result_queue,
):
    """
    One worker owns one SMTP connection.

    This avoids opening a fresh SMTP login for every email.
    """

    server = None

    try:
        # ----------------------------------------------------
        # LOGIN ONCE
        # ----------------------------------------------------

        server = create_smtp_connection(
            gmail,
            app_password,
        )

        result_queue.put(
            {
                "type": "worker_ready",
                "worker": worker_id,
            }
        )

        # ----------------------------------------------------
        # SEND RECIPIENTS
        # ----------------------------------------------------

        for index, recipient in enumerate(recipients):

            # Delay between sends handled by this worker.
            if index > 0:
                time.sleep(
                    SEND_DELAY_SECONDS
                )

            try:
                send_with_connection(
                    server=server,
                    gmail=gmail,
                    sender_name=sender_name,
                    subject=subject,
                    body=body,
                    is_html=is_html,
                    recipient=recipient,
                )

                result_queue.put(
                    {
                        "type": "progress",
                        "worker": worker_id,
                        "email": recipient,
                        "result": "sent",
                    }
                )

            except smtplib.SMTPServerDisconnected:
                # Try one clean reconnect.
                close_smtp(server)
                server = None

                try:
                    server = create_smtp_connection(
                        gmail,
                        app_password,
                    )

                    send_with_connection(
                        server=server,
                        gmail=gmail,
                        sender_name=sender_name,
                        subject=subject,
                        body=body,
                        is_html=is_html,
                        recipient=recipient,
                    )

                    result_queue.put(
                        {
                            "type": "progress",
                            "worker": worker_id,
                            "email": recipient,
                            "result": "sent",
                        }
                    )

                except Exception as retry_error:
                    result_queue.put(
                        {
                            "type": "progress",
                            "worker": worker_id,
                            "email": recipient,
                            "result": "failed",
                            "error": str(retry_error),
                        }
                    )

            except smtplib.SMTPRecipientsRefused as exc:
                result_queue.put(
                    {
                        "type": "progress",
                        "worker": worker_id,
                        "email": recipient,
                        "result": "failed",
                        "error": "Recipient refused by SMTP server.",
                        "detail": str(exc),
                    }
                )

            except smtplib.SMTPAuthenticationError as exc:
                # Authentication errors are batch-level serious
                # errors, but we still report the current email.
                result_queue.put(
                    {
                        "type": "progress",
                        "worker": worker_id,
                        "email": recipient,
                        "result": "failed",
                        "error": "SMTP authentication failed.",
                        "detail": str(exc),
                    }
                )

                # Stop this worker because credentials are invalid.
                break

            except smtplib.SMTPException as exc:
                result_queue.put(
                    {
                        "type": "progress",
                        "worker": worker_id,
                        "email": recipient,
                        "result": "failed",
                        "error": "SMTP error.",
                        "detail": str(exc),
                    }
                )

            except Exception as exc:
                result_queue.put(
                    {
                        "type": "progress",
                        "worker": worker_id,
                        "email": recipient,
                        "result": "failed",
                        "error": str(exc),
                    }
                )

    except smtplib.SMTPAuthenticationError as exc:
        result_queue.put(
            {
                "type": "worker_error",
                "worker": worker_id,
                "error": "SMTP authentication failed.",
                "detail": str(exc),
            }
        )

    except smtplib.SMTPException as exc:
        result_queue.put(
            {
                "type": "worker_error",
                "worker": worker_id,
                "error": "SMTP connection error.",
                "detail": str(exc),
            }
        )

    except Exception as exc:
        result_queue.put(
            {
                "type": "worker_error",
                "worker": worker_id,
                "error": str(exc),
            }
        )

    finally:
        close_smtp(server)

        result_queue.put(
            {
                "type": "worker_done",
                "worker": worker_id,
            }
        )


# ============================================================
# SPLIT RECIPIENTS
# ============================================================

def split_recipients(recipients, workers):
    """
    Split recipients into balanced chunks.

    Example:
        25 recipients / 2 workers
        -> approximately 13 + 12
    """

    chunks = [
        []
        for _ in range(workers)
    ]

    for index, recipient in enumerate(recipients):
        chunks[index % workers].append(
            recipient
        )

    return [
        chunk
        for chunk in chunks
        if chunk
    ]


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if authenticated():
        return redirect(
            url_for("home")
        )

    error = None

    if request.method == "POST":

        password = request.form.get(
            "password",
            "",
        )

        token = request.form.get(
            "cf-turnstile-response",
            "",
        )

        remote_ip = request.headers.get(
            "X-Forwarded-For",
            request.remote_addr,
        )

        # -----------------------------------------------
        # Turnstile
        # -----------------------------------------------

        turnstile_ok, turnstile_error = (
            verify_turnstile(
                token,
                remote_ip,
            )
        )

        if not turnstile_ok:
            error = turnstile_error

        # -----------------------------------------------
        # Password
        # -----------------------------------------------

        elif not secrets.compare_digest(
            password,
            LOGIN_PASSWORD,
        ):
            error = "Invalid password."

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
        turnstile_enabled=turnstile_enabled(),
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
def home():

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
        turnstile_enabled=turnstile_enabled(),
    )


# ============================================================
# SEND BATCH
# ============================================================

@app.route(
    "/send-batch",
    methods=["POST"],
)
def send_batch():

    # --------------------------------------------------------
    # Authentication
    # --------------------------------------------------------

    if not authenticated():
        return jsonify(
            {
                "error": "Authentication required.",
                "login_required": True,
            }
        ), 401

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    try:
        data = request.get_json(
            silent=True
        ) or {}

    except Exception:
        return jsonify(
            {
                "error": "Invalid JSON request."
            }
        ), 400

    # --------------------------------------------------------
    # Fields
    # --------------------------------------------------------

    sender_name = str(
        data.get(
            "sender_name",
            "",
        )
    ).strip()

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

    recipients_input = data.get(
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
    # Basic validation
    # --------------------------------------------------------

    if not sender_name:
        return jsonify(
            {
                "error": "Sender Name is required."
            }
        ), 400

    if not is_valid_email(gmail):
        return jsonify(
            {
                "error": "Enter a valid Gmail address."
            }
        ), 400

    if not app_password:
        return jsonify(
            {
                "error": "Google App Password is required."
            }
        ), 400

    if not subject:
        return jsonify(
            {
                "error": "Subject is required."
            }
        ), 400

    if not body.strip():
        return jsonify(
            {
                "error": "Email body is required."
            }
        ), 400

    # --------------------------------------------------------
    # Recipients
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
                "error": "Recipients must be a list."
            }
        ), 400

    clean_recipients = []
    seen = set()

    for item in recipients_input:

        email = normalize_email(
            str(item)
        )

        if not email:
            continue

        if not is_valid_email(email):
            continue

        if email in seen:
            continue

        seen.add(email)
        clean_recipients.append(email)

        if len(clean_recipients) >= MAX_RECIPIENTS:
            break

    if not clean_recipients:
        return jsonify(
            {
                "error": "No valid recipients found."
            }
        ), 400

    # --------------------------------------------------------
    # Turnstile
    # --------------------------------------------------------

    remote_ip = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr,
    )

    turnstile_ok, turnstile_error = (
        verify_turnstile(
            turnstile_token,
            remote_ip,
        )
    )

    if not turnstile_ok:
        return jsonify(
            {
                "error": turnstile_error
            }
        ), 400

    # --------------------------------------------------------
    # Prepare worker chunks
    # --------------------------------------------------------

    worker_count = min(
        MAX_PARALLEL_SENDS,
        len(clean_recipients),
    )

    chunks = split_recipients(
        clean_recipients,
        worker_count,
    )

    result_queue = Queue()

    threads = []

    # --------------------------------------------------------
    # Start workers
    # --------------------------------------------------------

    for worker_id, chunk in enumerate(
        chunks,
        start=1,
    ):

        thread = Thread(
            target=smtp_worker,
            kwargs={
                "worker_id": worker_id,
                "recipients": chunk,
                "gmail": gmail,
                "app_password": app_password,
                "sender_name": sender_name,
                "subject": subject,
                "body": body,
                "is_html": is_html,
                "result_queue": result_queue,
            },
            daemon=True,
        )

        thread.start()
        threads.append(thread)

    # --------------------------------------------------------
    # Streaming generator
    # --------------------------------------------------------

    def generate():

        total = len(
            clean_recipients
        )

        sent_count = 0
        failed_count = 0
        completed_count = 0

        workers_done = 0

        # -----------------------------------------------
        # START EVENT
        # -----------------------------------------------

        yield (
            json.dumps(
                {
                    "type": "start",
                    "total": total,
                    "sent": 0,
                    "failed": 0,
                    "remaining": total,
                    "parallel": worker_count,
                    "delay": SEND_DELAY_SECONDS,
                }
            )
            + "\n"
        )

        # -----------------------------------------------
        # Read worker results
        # -----------------------------------------------

        while workers_done < len(threads):

            event = result_queue.get()

            event_type = event.get(
                "type"
            )

            # -------------------------------------------
            # Worker ready
            # -------------------------------------------

            if event_type == "worker_ready":

                yield (
                    json.dumps(
                        {
                            "type": "worker_ready",
                            "worker": event.get(
                                "worker"
                            ),
                        }
                    )
                    + "\n"
                )

            # -------------------------------------------
            # Progress
            # -------------------------------------------

            elif event_type == "progress":

                result = event.get(
                    "result"
                )

                if result == "sent":
                    sent_count += 1
                else:
                    failed_count += 1

                completed_count += 1

                remaining = max(
                    0,
                    total - completed_count,
                )

                progress_event = {
                    "type": "progress",
                    "email": event.get(
                        "email"
                    ),
                    "result": result,
                    "sent": sent_count,
                    "failed": failed_count,
                    "completed": completed_count,
                    "total": total,
                    "remaining": remaining,
                }

                if event.get("error"):
                    progress_event["error"] = event.get(
                        "error"
                    )

                if event.get("detail"):
                    progress_event["detail"] = event.get(
                        "detail"
                    )

                yield (
                    json.dumps(
                        progress_event
                    )
                    + "\n"
                )

            # -------------------------------------------
            # Worker error
            # -------------------------------------------

            elif event_type == "worker_error":

                yield (
                    json.dumps(
                        {
                            "type": "worker_error",
                            "worker": event.get(
                                "worker"
                            ),
                            "error": event.get(
                                "error"
                            ),
                            "detail": event.get(
                                "detail"
                            ),
                        }
                    )
                    + "\n"
                )

            # -------------------------------------------
            # Worker finished
            # -------------------------------------------

            elif event_type == "worker_done":

                workers_done += 1

                yield (
                    json.dumps(
                        {
                            "type": "worker_done",
                            "worker": event.get(
                                "worker"
                            ),
                        }
                    )
                    + "\n"
                )

        # -----------------------------------------------
        # Make sure threads have exited
        # -----------------------------------------------

        for thread in threads:
            thread.join(
                timeout=2
            )

        # -----------------------------------------------
        # COMPLETE EVENT
        # -----------------------------------------------

        yield (
            json.dumps(
                {
                    "type": "complete",
                    "total": total,
                    "sent": sent_count,
                    "failed": failed_count,
                    "completed": completed_count,
                    "remaining": max(
                        0,
                        total - completed_count,
                    ),
                }
            )
            + "\n"
        )

    # --------------------------------------------------------
    # Streaming response
    # --------------------------------------------------------

    response = Response(
        stream_with_context(
            generate()
        ),
        mimetype="application/x-ndjson",
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate"
    )

    response.headers["Pragma"] = "no-cache"

    response.headers["Expires"] = "0"

    response.headers["X-Accel-Buffering"] = "no"

    response.headers["Connection"] = "keep-alive"

    return response


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return jsonify(
        {
            "status": "ok",
            "service": "secure-mail-console",
            "smtp_host": SMTP_HOST,
            "smtp_port": SMTP_PORT,
            "parallel": MAX_PARALLEL_SENDS,
            "max_recipients": MAX_RECIPIENTS,
            "turnstile_enabled": turnstile_enabled(),
        }
    )


# ============================================================
# SECURITY HEADERS
# ============================================================

@app.after_request
def add_security_headers(response):

    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff",
    )

    response.headers.setdefault(
        "X-Frame-Options",
        "SAMEORIGIN",
    )

    response.headers.setdefault(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
    )

    return response


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

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
import queue
import threading

from concurrent.futures import ThreadPoolExecutor

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path


# =========================================================
# APP
# =========================================================

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

# Required by Vercel
handler = app


# =========================================================
# ENVIRONMENT VARIABLES
# =========================================================

SESSION_SECRET = os.environ.get(
    "SESSION_SECRET",
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

LOGIN_PASSWORD = os.environ.get(
    "LOGIN_PASSWORD",
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

# Two controlled SMTP workers.
# This is intentionally kept at 2 for stable sending.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# Small pacing delay between messages on the same connection.
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

    return bool(EMAIL_RE.fullmatch(value))


def normalize_email(value):
    return str(value or "").strip().lower()


def authenticated():
    return session.get("authenticated") is True


def clean_header(value, max_length=998):
    value = str(value or "")
    value = value.replace("\r", " ")
    value = value.replace("\n", " ")
    return value.strip()[:max_length]


# =========================================================
# PERSONALIZATION
# =========================================================

def personalize_template(template, recipient):
    result = str(template or "")

    values = {
        "{{hi}}": str(recipient.get("hi", "") or ""),
        "{{hello}}": str(recipient.get("hello", "") or ""),
        "{{thanks}}": str(recipient.get("thanks", "") or ""),
        "{{name}}": str(recipient.get("name", "") or ""),
        "{{email}}": str(recipient.get("email", "") or ""),
        "{{ref_code}}": str(
            recipient.get("ref_code", "") or ""
        ),
    }

    for placeholder, value in values.items():
        result = result.replace(
            placeholder,
            value,
        )

    return result


# =========================================================
# HTML TO PLAIN TEXT
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

    return text.strip()


# =========================================================
# TURNSTILE
# =========================================================

def verify_turnstile(token, remote_ip=None):

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

    return redirect(url_for("home"))


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
        200,
    )

    subject = clean_header(
        subject,
        998,
    )

    body = str(
        body or ""
    ).replace(
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

    message["MIME-Version"] = "1.0"

    return message


# =========================================================
# NORMALIZE RECIPIENT
# =========================================================

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

    name = str(
        item.get("name", "")
        or ""
    ).strip()

    hi = str(
        item.get("hi", "")
        or ""
    ).strip()

    hello = str(
        item.get("hello", "")
        or ""
    ).strip()

    thanks = str(
        item.get("thanks", "")
        or ""
    ).strip()

    ref_code = str(
        item.get("ref_code", "")
        or ""
    ).strip()

    name = (
        name
        .replace("\r", " ")
        .replace("\n", " ")
    )

    hi = (
        hi
        .replace("\r", " ")
        .replace("\n", " ")
    )

    hello = (
        hello
        .replace("\r", " ")
        .replace("\n", " ")
    )

    thanks = (
        thanks
        .replace("\r", " ")
        .replace("\n", " ")
    )

    ref_code = (
        ref_code
        .replace("\r", " ")
        .replace("\n", " ")
    )

    return {
        "email": email,
        "name": name[:200],
        "hi": hi[:100],
        "hello": hello[:100],
        "thanks": thanks[:100],
        "ref_code": ref_code[:200],
    }


# =========================================================
# CREATE SMTP CONNECTION
# =========================================================

def create_smtp_connection(
    gmail,
    app_password,
):

    clean_app_password = re.sub(
        r"\s+",
        "",
        str(app_password or ""),
    )

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
        clean_app_password,
    )

    return server


# =========================================================
# SEND RECIPIENT
# =========================================================

def send_recipient(
    server,
    gmail,
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

    personalized_subject = personalize_template(
        subject,
        recipient_data,
    )

    personalized_body = personalize_template(
        body,
        recipient_data,
    )

    message = build_message(
        gmail=gmail,
        sender_name=sender_name,
        subject=personalized_subject,
        body=personalized_body,
        is_html=is_html,
        recipient=recipient,
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
            "error": "SMTP refused recipient.",
        }

    return {
        "email": recipient,
        "result": "sent",
    }


# =========================================================
# SMTP WORKER
# =========================================================

def smtp_worker(
    worker_items,
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    result_queue,
    stop_event,
):

    server = None

    try:

        # One authenticated connection for this worker.
        server = create_smtp_connection(
            gmail,
            app_password,
        )

        for index, recipient_data in enumerate(
            worker_items
        ):

            if stop_event.is_set():
                break

            recipient = recipient_data["email"]

            try:

                result = send_recipient(
                    server=server,
                    gmail=gmail,
                    sender_name=sender_name,
                    subject=subject,
                    body=body,
                    is_html=is_html,
                    recipient_data=recipient_data,
                )

                result_queue.put(result)

            except smtplib.SMTPAuthenticationError:

                result_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error":
                        "Gmail authentication failed. Check Gmail and App Password.",
                })

                # Authentication failure affects this connection,
                # so do not continue attempting sends on it.
                break

            except smtplib.SMTPRecipientsRefused:

                result_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error":
                        "SMTP recipient was refused.",
                })

            except (
                smtplib.SMTPConnectError,
                smtplib.SMTPServerDisconnected,
                TimeoutError,
                ConnectionError,
            ):

                result_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error":
                        "SMTP connection or timeout error.",
                })

                break

            except smtplib.SMTPException as exc:

                result_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error": str(exc)[:500],
                })

            except Exception as exc:

                result_queue.put({
                    "email": recipient,
                    "result": "failed",
                    "error": str(exc)[:500],
                })

            # Pace messages on the same SMTP connection.
            if (
                index < len(worker_items) - 1
                and SEND_DELAY_SECONDS > 0
            ):

                time.sleep(
                    SEND_DELAY_SECONDS
                )

    except smtplib.SMTPAuthenticationError:

        # If login itself fails, mark the entire
        # unprocessed worker queue as failed.
        for recipient_data in worker_items:

            result_queue.put({
                "email":
                    recipient_data["email"],
                "result":
                    "failed",
                "error":
                    "Gmail authentication failed. Check Gmail and App Password.",
            })

    except Exception as exc:

        for recipient_data in worker_items:

            result_queue.put({
                "email":
                    recipient_data["email"],
                "result":
                    "failed",
                "error":
                    str(exc)[:500],
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


# =========================================================
# SPLIT WORK
# =========================================================

def split_into_workers(items, workers):

    if not items:
        return []

    workers = max(
        1,
        min(
            workers,
            len(items),
        ),
    )

    chunks = [
        []
        for _ in range(workers)
    ]

    for index, item in enumerate(items):
        chunks[index % workers].append(item)

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
    methods=["POST"],
)
def send_batch():

    if not authenticated():

        return jsonify({
            "success": False,
            "message":
                "Authentication required.",
            "login_required":
                True,
        }), 401

    data = request.get_json(
        silent=True
    )

    if not isinstance(
        data,
        dict,
    ):

        return jsonify({
            "success": False,
            "message":
                "Invalid JSON request.",
        }), 400

    sender_name = clean_header(
        data.get(
            "sender_name",
            "",
        ),
        200,
    )

    gmail = clean_header(
        data.get(
            "gmail",
            "",
        ),
        254,
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

    # =====================================================
    # RECIPIENT CLEANUP
    # =====================================================

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

        result_queue = queue.Queue()

        stop_event = threading.Event()

        chunks = split_into_workers(
            clean_recipients,
            MAX_PARALLEL_SENDS,
        )

        yield (
            json.dumps(
                {
                    "type": "start",
                    "total": total,
                    "sent": 0,
                    "failed": 0,
                    "remaining": total,
                    "parallel":
                        len(chunks),
                    "delay":
                        SEND_DELAY_SECONDS,
                },
                ensure_ascii=False,
            )
            + "\n"
        )

        executor = ThreadPoolExecutor(
            max_workers=len(chunks)
        )

        futures = []

        try:

            for chunk in chunks:

                future = executor.submit(
                    smtp_worker,
                    chunk,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    result_queue,
                    stop_event,
                )

                futures.append(future)

            processed = 0

            while processed < total:

                try:

                    result = result_queue.get(
                        timeout=0.5
                    )

                except queue.Empty:

                    # If every worker has stopped but
                    # the queue is unexpectedly empty,
                    # prevent an infinite wait.
                    if all(
                        future.done()
                        for future in futures
                    ):
                        break

                    continue

                processed += 1

                recipient = result.get(
                    "email",
                    "",
                )

                if result.get("result") == "sent":

                    sent_count += 1

                    event = {
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
                    }

                else:

                    failed_count += 1

                    event = {
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
                    }

                yield (
                    json.dumps(
                        event,
                        ensure_ascii=False,
                    )
                    + "\n"
                )

        finally:

            stop_event.set()

            executor.shutdown(
                wait=True
            )

        # Any worker failure that somehow left
        # recipients unreported is accounted for.
        remaining_unreported = (
            total
            - sent_count
            - failed_count
        )

        if remaining_unreported > 0:

            failed_count += (
                remaining_unreported
            )

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

    # =====================================================
    # RESPONSE
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
        "status":
            "ok",
        "service":
            "YATENDRA Mail Console",
        "mailer":
            "Gmail SMTP",
        "parallel_sends":
            MAX_PARALLEL_SENDS,
        "send_delay":
            SEND_DELAY_SECONDS,
        "max_recipients":
            MAX_RECIPIENTS,
        "placeholders": [
            "{{hi}}",
            "{{hello}}",
            "{{thanks}}",
            "{{name}}",
            "{{email}}",
            "{{ref_code}}",
        ],
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

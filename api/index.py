# api/index.py

from flask import Flask, request, session, redirect, url_for, render_template, Response, jsonify
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import os
import re
import ssl
import smtplib
import json
import time
import urllib.request
import urllib.parse

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid


# ============================================================
# PATH / APP
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
# CONFIG
# ============================================================

app.secret_key = os.environ.get("SESSION_SECRET", "change-this-secret")

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 25

# Keep concurrency controlled.
MAX_PARALLEL_SENDS = 3

# Small pacing delay before each SMTP transaction.
SEND_DELAY_SECONDS = 1.8


# ============================================================
# EMAIL VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def valid_email(email):
    if not isinstance(email, str):
        return False

    email = email.strip()

    if len(email) > 254:
        return False

    return bool(EMAIL_RE.match(email))


# ============================================================
# AUTH
# ============================================================

@app.before_request
def require_login():
    public_paths = {
        "/login",
        "/health",
        "/static/",
    }

    path = request.path

    if path == "/login":
        return None

    if path == "/health":
        return None

    if path.startswith("/static/"):
        return None

    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return None


# ============================================================
# LOGIN
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    password = request.form.get("password", "")

    if not LOGIN_PASSWORD:
        return "LOGIN_PASSWORD is not configured.", 500

    if password == LOGIN_PASSWORD:
        session.clear()
        session["logged_in"] = True

        return redirect(url_for("home"))

    return render_template(
        "login.html",
        error="Invalid password."
    ), 401


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY
    )


# ============================================================
# TURNSTILE
# ============================================================

def verify_turnstile(token, remote_ip=None):

    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."

    if not token:
        return False, "Turnstile verification is required."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    try:
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=encoded,
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            method="POST",
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

        if result.get("success") is True:
            return True, None

        return False, "Turnstile verification failed."

    except Exception as exc:
        return False, f"Turnstile error: {exc}"


# ============================================================
# TEMPLATE PERSONALIZATION
# ============================================================

def personalize_template(template, recipient):

    if template is None:
        return ""

    template = str(template)

    if not isinstance(recipient, dict):
        recipient = {
            "email": str(recipient or "")
        }

    values = {
        "{{hi}}": str(recipient.get("hi", "") or ""),
        "{{hello}}": str(recipient.get("hello", "") or ""),
        "{{thanks}}": str(recipient.get("thanks", "") or ""),
        "{{name}}": str(recipient.get("name", "") or ""),
        "{{email}}": str(recipient.get("email", "") or ""),
        "{{ref_code}}": str(recipient.get("ref_code", "") or ""),
    }

    for placeholder, value in values.items():
        template = template.replace(placeholder, value)

    return template


# ============================================================
# HTML -> PLAIN TEXT
# ============================================================

def html_to_plain_text(html):

    if not html:
        return ""

    text = html

    text = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>",
        "",
        text
    )

    text = re.sub(
        r"(?i)<br\s*/?>",
        "\n",
        text
    )

    text = re.sub(
        r"(?i)</p\s*>",
        "\n\n",
        text
    )

    text = re.sub(
        r"(?i)</div\s*>",
        "\n",
        text
    )

    text = re.sub(
        r"(?i)<li\s*>",
        "\n• ",
        text
    )

    text = re.sub(
        r"<[^>]+>",
        "",
        text
    )

    text = re.sub(
        r"[ \t]+",
        " ",
        text
    )

    text = re.sub(
        r"\n[ \t]+",
        "\n",
        text
    )

    text = re.sub(
        r"\n{3,}",
        "\n\n",
        text
    )

    return text.strip()


# ============================================================
# CLEAN HEADER VALUE
# ============================================================

def clean_header_value(value):

    if value is None:
        return ""

    # Prevent CR/LF header injection.
    value = str(value)
    value = value.replace("\r", " ")
    value = value.replace("\n", " ")

    return value.strip()


# ============================================================
# BUILD EMAIL
# ============================================================

def build_message(
    sender_name,
    sender_email,
    recipient,
    subject,
    body,
    is_html=False
):

    recipient_email = recipient["email"]

    sender_name = clean_header_value(sender_name)
    sender_email = clean_header_value(sender_email)
    recipient_email = clean_header_value(recipient_email)
    subject = clean_header_value(subject)

    if is_html:

        plain_body = html_to_plain_text(body)

        msg = MIMEMultipart("alternative")

        plain_part = MIMEText(
            plain_body,
            "plain",
            "utf-8"
        )

        html_part = MIMEText(
            body,
            "html",
            "utf-8"
        )

        msg.attach(plain_part)
        msg.attach(html_part)

    else:

        msg = MIMEText(
            body,
            "plain",
            "utf-8"
        )

    # Authenticated sender identity.
    if sender_name:
        msg["From"] = formataddr(
            (sender_name, sender_email)
        )
    else:
        msg["From"] = sender_email

    msg["To"] = recipient_email
    msg["Subject"] = subject

    # Standard RFC-compatible headers.
    msg["Date"] = formatdate(
        localtime=True
    )

    msg["Message-ID"] = make_msgid()

    return msg


# ============================================================
# NORMALIZE RECIPIENT
# ============================================================

def normalize_recipient(item):

    if isinstance(item, str):

        email = item.strip()

        if not valid_email(email):
            return None

        return {
            "email": email,
            "name": "",
            "hi": "",
            "hello": "",
            "thanks": "",
            "ref_code": "",
        }

    if not isinstance(item, dict):
        return None

    email = str(
        item.get("email", "") or ""
    ).strip()

    if not valid_email(email):
        return None

    return {
        "email": email,

        "name": str(
            item.get("name", "") or ""
        ).strip(),

        "hi": str(
            item.get("hi", "") or ""
        ).strip(),

        "hello": str(
            item.get("hello", "") or ""
        ).strip(),

        "thanks": str(
            item.get("thanks", "") or ""
        ).strip(),

        "ref_code": str(
            item.get("ref_code", "") or ""
        ).strip(),
    }


# ============================================================
# APP PASSWORD CLEANUP
# ============================================================

def clean_app_password(value):

    if not value:
        return ""

    # Google App Passwords are sometimes pasted with spaces.
    return re.sub(
        r"\s+",
        "",
        str(value)
    )


# ============================================================
# SEND ONE EMAIL
# ============================================================

def send_one_email(
    sender_name,
    gmail,
    app_password,
    subject,
    body,
    is_html,
    recipient
):

    recipient_email = recipient["email"]

    try:

        # Controlled pacing.
        if SEND_DELAY_SECONDS > 0:
            time.sleep(SEND_DELAY_SECONDS)

        personalized_subject = personalize_template(
            subject,
            recipient
        )

        personalized_body = personalize_template(
            body,
            recipient
        )

        msg = build_message(
            sender_name=sender_name,
            sender_email=gmail,
            recipient=recipient,
            subject=personalized_subject,
            body=personalized_body,
            is_html=is_html
        )

        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=SMTP_TIMEOUT,
            context=context
        ) as smtp:

            smtp.login(
                gmail,
                app_password
            )

            refused = smtp.sendmail(
                gmail,
                [recipient_email],
                msg.as_string()
            )

            # SMTP accepted/rejected recipients are checked.
            if refused:

                details = refused.get(
                    recipient_email,
                    refused
                )

                return {
                    "email": recipient_email,
                    "status": "failed",
                    "message": f"SMTP refused recipient: {details}",
                }

        return {
            "email": recipient_email,
            "status": "sent",
            "message": "SMTP accepted the message.",
        }

    except smtplib.SMTPAuthenticationError:

        return {
            "email": recipient_email,
            "status": "failed",
            "message": (
                "Gmail authentication failed. "
                "Use the correct Gmail address and Google App Password."
            ),
        }

    except smtplib.SMTPRecipientsRefused as exc:

        return {
            "email": recipient_email,
            "status": "failed",
            "message": f"Recipient refused: {exc}",
        }

    except smtplib.SMTPServerDisconnected as exc:

        return {
            "email": recipient_email,
            "status": "failed",
            "message": f"SMTP server disconnected: {exc}",
        }

    except smtplib.SMTPException as exc:

        return {
            "email": recipient_email,
            "status": "failed",
            "message": f"SMTP error: {exc}",
        }

    except TimeoutError:

        return {
            "email": recipient_email,
            "status": "failed",
            "message": "SMTP connection timed out.",
        }

    except Exception as exc:

        return {
            "email": recipient_email,
            "status": "failed",
            "message": str(exc),
        }


# ============================================================
# STREAMING HELPERS
# ============================================================

def ndjson(data):

    return json.dumps(
        data,
        ensure_ascii=False
    ) + "\n"


# ============================================================
# SEND BATCH
# ============================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():

    try:

        data = request.get_json(
            silent=True
        ) or {}

        # ----------------------------------------------------
        # BASIC INPUTS
        # ----------------------------------------------------

        sender_name = clean_header_value(
            data.get("sender_name", "")
        )

        gmail = str(
            data.get("gmail", "") or ""
        ).strip()

        app_password = clean_app_password(
            data.get("app_password", "")
        )

        subject = clean_header_value(
            data.get("subject", "")
        )

        body = data.get(
            "body",
            ""
        )

        is_html = bool(
            data.get("is_html", False)
        )

        recipients_raw = data.get(
            "recipients",
            []
        )

        turnstile_token = data.get(
            "turnstile_token",
            ""
        )

        # ----------------------------------------------------
        # VALIDATION
        # ----------------------------------------------------

        if not valid_email(gmail):

            return jsonify({
                "ok": False,
                "error": "Invalid Gmail address."
            }), 400

        if not app_password:

            return jsonify({
                "ok": False,
                "error": "Google App Password is required."
            }), 400

        if not subject.strip():

            return jsonify({
                "ok": False,
                "error": "Subject is required."
            }), 400

        if not str(body).strip():

            return jsonify({
                "ok": False,
                "error": "Email body is required."
            }), 400

        if not isinstance(
            recipients_raw,
            list
        ):

            return jsonify({
                "ok": False,
                "error": "Recipients must be an array."
            }), 400

        if not recipients_raw:

            return jsonify({
                "ok": False,
                "error": "No recipients supplied."
            }), 400

        if len(recipients_raw) > MAX_RECIPIENTS:

            return jsonify({
                "ok": False,
                "error": (
                    f"Maximum {MAX_RECIPIENTS} recipients "
                    "are allowed per batch."
                )
            }), 400

        # ----------------------------------------------------
        # TURNSTILE
        # ----------------------------------------------------

        verified, turnstile_error = verify_turnstile(
            turnstile_token,
            request.remote_addr
        )

        if not verified:

            return jsonify({
                "ok": False,
                "error": turnstile_error
            }), 400

        # ----------------------------------------------------
        # NORMALIZE + DEDUPLICATE
        # ----------------------------------------------------

        recipients = []

        seen = set()

        for item in recipients_raw:

            recipient = normalize_recipient(
                item
            )

            if not recipient:
                continue

            email_key = recipient["email"].lower()

            if email_key in seen:
                continue

            seen.add(email_key)
            recipients.append(recipient)

        if not recipients:

            return jsonify({
                "ok": False,
                "error": "No valid recipients found."
            }), 400

        # ----------------------------------------------------
        # STREAM RESPONSE
        # ----------------------------------------------------

        def generate():

            total = len(recipients)

            sent_count = 0
            failed_count = 0

            yield ndjson({
                "type": "start",
                "total": total,
                "parallel": MAX_PARALLEL_SENDS,
                "delay": SEND_DELAY_SECONDS,
            })

            # ------------------------------------------------
            # CONTROLLED PARALLELISM
            # ------------------------------------------------

            with ThreadPoolExecutor(
                max_workers=MAX_PARALLEL_SENDS
            ) as executor:

                future_map = {}

                for recipient in recipients:

                    future = executor.submit(
                        send_one_email,
                        sender_name,
                        gmail,
                        app_password,
                        subject,
                        str(body),
                        is_html,
                        recipient
                    )

                    future_map[future] = recipient

                completed = 0

                for future in as_completed(
                    future_map
                ):

                    recipient = future_map[future]

                    try:

                        result = future.result()

                    except Exception as exc:

                        result = {
                            "email": recipient["email"],
                            "status": "failed",
                            "message": str(exc),
                        }

                    completed += 1

                    if result["status"] == "sent":
                        sent_count += 1
                    else:
                        failed_count += 1

                    yield ndjson({
                        "type": "progress",
                        "index": completed,
                        "total": total,
                        "email": result["email"],
                        "status": result["status"],
                        "message": result["message"],
                        "sent": sent_count,
                        "failed": failed_count,
                    })

            # ------------------------------------------------
            # COMPLETE
            # ------------------------------------------------

            yield ndjson({
                "type": "complete",
                "total": total,
                "sent": sent_count,
                "failed": failed_count,
            })

        response = Response(
            generate(),
            mimetype="application/x-ndjson"
        )

        response.headers["Cache-Control"] = (
            "no-cache, no-store, must-revalidate"
        )

        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        response.headers["X-Accel-Buffering"] = "no"
        response.headers["X-Content-Type-Options"] = "nosniff"

        return response

    except Exception as exc:

        return jsonify({
            "ok": False,
            "error": str(exc)
        }), 500


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return jsonify({
        "ok": True,
        "service": "gmail-smtp-mail-sender",

        "smtp": {
            "host": SMTP_HOST,
            "port": SMTP_PORT,
            "ssl": True,
            "timeout": SMTP_TIMEOUT,
        },

        "limits": {
            "max_recipients": MAX_RECIPIENTS,
            "max_parallel_sends": MAX_PARALLEL_SENDS,
            "send_delay_seconds": SEND_DELAY_SECONDS,
        },

        "placeholders": [
            "{{hi}}",
            "{{hello}}",
            "{{thanks}}",
            "{{name}}",
            "{{email}}",
            "{{ref_code}}",
        ],

        # Ref code is NEVER automatically generated.
        "ref_code_auto_generated": False,

        # No unrelated links are automatically inserted.
        "automatic_links": False,

        "turnstile_configured": bool(
            TURNSTILE_SECRET_KEY
        ),

        "login_configured": bool(
            LOGIN_PASSWORD
        ),
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
                "5000"
            )
        ),
        debug=False
    )

```python
import os
import re
import ssl
import smtplib
import logging
import random

from email.message import EmailMessage
from email.utils import formataddr

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
application = app

logging.basicConfig(level=logging.INFO)

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()

try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
except (TypeError, ValueError):
    SMTP_PORT = 465

# Speed is configured in Vercel, in milliseconds.
# 500 = 0.5 seconds. No delay is added by this Python function.
try:
    MAIL_GAP_MS = max(
        0, min(int(os.environ.get("MAIL_GAP_MS", "500")), 60000)
    )
except (TypeError, ValueError):
    MAIL_GAP_MS = 500

SMTP_TIMEOUT = 20
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app.secret_key = SESSION_SECRET or None
app.config.update(
    MAX_CONTENT_LENGTH=1_000_000,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("VERCEL")),
)


def valid_email(value):
    return isinstance(value, str) and bool(
        EMAIL_RE.fullmatch(value.strip())
    )


def logged_in():
    return session.get("logged_in") is True


def expand_spintax(text):
    pattern = r"\{([^{}|]+(?:\|[^{}|]+)+)\}"
    return re.sub(
        pattern,
        lambda m: random.choice(m.group(1).split("|")),
        text,
    )


def send_smtp(recipient, sender, password, sender_name,
              subject, body, html_mode):
    message = EmailMessage()
    message["From"] = formataddr((sender_name or sender, sender))
    message["To"] = recipient
    message["Subject"] = expand_spintax(subject)

    content = expand_spintax(body)

    if html_mode:
        message.set_content(
            "Please view this message in an HTML-capable email client."
        )
        message.add_alternative(content, subtype="html")
    else:
        message.set_content(content)

    context = ssl.create_default_context()

    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(
                SMTP_HOST, SMTP_PORT,
                timeout=SMTP_TIMEOUT, context=context
            ) as smtp:
                smtp.login(sender, password)
                refused = smtp.send_message(message)
        else:
            with smtplib.SMTP(
                SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT
            ) as smtp:
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
                smtp.login(sender, password)
                refused = smtp.send_message(message)

        if refused:
            return False, "Recipient rejected by SMTP."

        return True, (
            "SMTP accepted the message; inbox placement is not guaranteed."
        )

    except smtplib.SMTPAuthenticationError:
        return False, "Gmail login failed. Check the Gmail App Password."
    except smtplib.SMTPRecipientsRefused:
        return False, "Recipient rejected by SMTP."
    except smtplib.SMTPDataError as exc:
        return False, f"SMTP rejected the message (code {exc.smtp_code})."
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        app.logger.warning(
            "SMTP failure: %s; recipient=%s",
            type(exc).__name__, recipient
        )
        return False, f"SMTP connection/delivery error ({type(exc).__name__})."
    except Exception:
        app.logger.exception("Unexpected email sending error")
        return False, "Unexpected error. Check Vercel Runtime Logs."


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Request is too large."}), 413


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if not LOGIN_PASSWORD:
        error = "LOGIN_PASSWORD is not configured in Vercel."
    elif len(SESSION_SECRET) < 32:
        error = "SESSION_SECRET must be at least 32 characters."

    if request.method == "POST" and error is None:
        if request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "Incorrect password."

    return render_template("login.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    if not LOGIN_PASSWORD or len(SESSION_SECRET) < 32:
        return (
            "Configuration error. Check SESSION_SECRET and LOGIN_PASSWORD.",
            500,
        )

    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


@app.post("/send-batch")
def send_batch():
    if not LOGIN_PASSWORD or len(SESSION_SECRET) < 32:
        return jsonify({"error": "Server configuration is incomplete."}), 500

    if not logged_in():
        return jsonify({"error": "Session expired. Please log in again."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    sender = str(data.get("senderEmail", "")).strip()
    password = str(data.get("appPassword", "")).replace(" ", "")
    sender_name = str(data.get("senderName", "")).strip()[:100]
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True
    recipients = data.get("recipients")

    if data.get("consentConfirmed") is not True:
        return jsonify({"error": "Confirm recipient permission first."}), 400

    if not valid_email(sender) or not sender.lower().endswith("@gmail.com"):
        return jsonify({"error": "Enter a valid @gmail.com sender address."}), 400

    if not password:
        return jsonify({"error": "Google App Password is required."}), 400

    # One recipient per request enables accurate frontend live progress.
    if not isinstance(recipients, list) or len(recipients) != 1:
        return jsonify({
            "error": "Send one recipient per request for live progress."
        }), 400

    recipient = recipients[0]
    if not valid_email(recipient):
        return jsonify({"error": "Invalid recipient address."}), 400

    recipient = recipient.strip()

    if not subject or not body:
        return jsonify({"error": "Subject and message body are required."}), 400

    if len(subject) > 200 or len(body) > 500000:
        return jsonify({"error": "Subject or message is too long."}), 413

    success, detail = send_smtp(
        recipient, sender, password, sender_name,
        subject, body, html_mode
    )

    result = {
        "email": recipient,
        "status": "sent" if success else "failed",
        "detail": detail,
    }

    return jsonify({
        "total": 1,
        "sent": int(success),
        "failed": int(not success),
        "results": [result],
        "delayMs": MAIL_GAP_MS,
    })


# Vercel Python entry point
application = app
```

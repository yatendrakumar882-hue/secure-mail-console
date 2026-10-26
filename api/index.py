import os
import re
import ssl
import time
import random
import smtplib

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

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

app.secret_key = SESSION_SECRET
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("VERCEL"))

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()

try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
except ValueError:
    SMTP_PORT = 587

# Sending delay is controlled from Vercel Environment Variables.
try:
    MAIL_GAP_SECONDS = max(
        0.0,
        min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 60.0)
    )
except ValueError:
    MAIL_GAP_SECONDS = 1.0

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def expand_spintax(text):
    """Supports simple forms such as {Hello|Hi|Hey}."""
    return re.sub(
        r"\{([^{}|]+(?:\|[^{}|]+)+)\}",
        lambda match: random.choice(match.group(1).split("|")),
        text,
    )


def send_smtp(
    to_email,
    subject,
    body,
    sender_name,
    sender_email,
    app_password,
    html_mode=False,
):
    subject = expand_spintax(subject)
    body = expand_spintax(body)

    message = EmailMessage()
    message["From"] = formataddr((sender_name or sender_email, sender_email))
    message["To"] = to_email
    message["Subject"] = subject

    if html_mode:
        message.set_content(
            "This email contains HTML content. Please view it in an HTML-capable email client."
        )
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    context = ssl.create_default_context()

    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(
                SMTP_HOST, SMTP_PORT, timeout=20, context=context
            ) as server:
                server.login(sender_email, app_password)
                refused = server.send_message(message)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(sender_email, app_password)
                refused = server.send_message(message)

        if refused:
            return False, "Recipient rejected by SMTP server"

        return True, "SMTP accepted the message; inbox placement is not guaranteed."

    except smtplib.SMTPAuthenticationError:
        return False, "Gmail login failed. Check Gmail address and App Password."

    except smtplib.SMTPRecipientsRefused:
        return False, "Recipient address rejected by SMTP server"

    except smtplib.SMTPDataError as exc:
        return False, f"SMTP rejected message (code {exc.smtp_code})"

    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        return False, f"SMTP connection failed: {str(exc)[:160]}"


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if not LOGIN_PASSWORD:
            error = "Set LOGIN_PASSWORD in Vercel Environment Variables."
        elif len(SESSION_SECRET) < 32:
            error = "Set SESSION_SECRET to a random value of at least 32 characters."
        elif request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            error = "Incorrect password."

    return render_template("login.html", error=error)


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    if len(SESSION_SECRET) < 32:
        return jsonify({"error": "Configure a strong SESSION_SECRET."}), 500

    data = request.get_json(silent=True) or {}

    recipients = data.get("recipients", [])
    sender_email = str(data.get("senderEmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    sender_name = str(data.get("senderName", "")).strip()[:100]
    subject = str(data.get("subject", "")).strip()[:200]
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    if data.get("consentConfirmed") is not True:
        return jsonify({"error": "Confirm recipient permission first."}), 400

    if not EMAIL_RE.fullmatch(sender_email):
        return jsonify({"error": "Enter a valid sender email address."}), 400

    if not app_password:
        return jsonify({"error": "Enter your Google App Password."}), 400

    if not isinstance(recipients, list):
        return jsonify({"error": "Recipients must be a list."}), 400

    clean_recipients = []
    seen = set()

    for item in recipients:
        if isinstance(item, str):
            address = item.strip()
            key = address.lower()

            if EMAIL_RE.fullmatch(address) and key not in seen:
                clean_recipients.append(address)
                seen.add(key)

    if len(clean_recipients) != 1:
        return jsonify({
            "error": "Send one recipient per request for live progress."
        }), 400

    if not subject or not body:
        return jsonify({"error": "Subject and message are required."}), 400

    recipient = clean_recipients[0]

    ok, detail = send_smtp(
        recipient,
        subject,
        body,
        sender_name,
        sender_email,
        app_password,
        html_mode,
    )

    result = {
        "email": recipient,
        "status": "sent" if ok else "failed",
        "detail": detail,
    }

    return jsonify({
        "total": 1,
        "sent": 1 if ok else 0,
        "failed": 0 if ok else 1,
        "results": [result],
        "delaySeconds": MAIL_GAP_SECONDS,
    })

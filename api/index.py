import os
import re
import ssl
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
app.config["MAX_CONTENT_LENGTH"] = 1_000_000
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("VERCEL"))

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()

try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
except ValueError:
    SMTP_PORT = 465

try:
    MAIL_GAP_MS = max(
        0.0,
        min(float(os.environ.get("MAIL_GAP_MS", "1")), 60.0)
    )
except ValueError:
    MAIL_GAP_MS = 1.0

MAX_BATCH_SIZE = 10
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def expand_spintax(text):
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
    message = EmailMessage()
    message["From"] = formataddr((sender_name or sender_email, sender_email))
    message["To"] = to_email
    message["Subject"] = expand_spintax(subject)

    content = expand_spintax(body)

    if html_mode:
        message.set_content("Please view this message in an HTML-capable email client.")
        message.add_alternative(content, subtype="html")
    else:
        message.set_content(content)

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
            return False, "Recipient rejected by SMTP server."

        return True, "SMTP accepted the message; inbox placement is not guaranteed."

    except smtplib.SMTPAuthenticationError:
        return False, "Gmail authentication failed. Check the App Password."
    except smtplib.SMTPRecipientsRefused:
        return False, "Recipient address was rejected by SMTP."
    except smtplib.SMTPDataError as exc:
        return False, f"SMTP rejected the message (code {exc.smtp_code})."
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        return False, f"SMTP error: {str(exc)[:160]}"


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
            error = "SESSION_SECRET must contain at least 32 characters."
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
        return jsonify({"error": "Your session expired. Please sign in again."}), 401

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
        return jsonify({"error": "Enter the Gmail App Password."}), 400

    if not isinstance(recipients, list) or len(recipients) != 1:
        return jsonify({
            "error": "Send one recipient per request for live progress."
        }), 400

    recipient = recipients[0]
    if not isinstance(recipient, str) or not EMAIL_RE.fullmatch(recipient.strip()):
        return jsonify({"error": "Enter a valid recipient email address."}), 400

    if not subject or not body:
        return jsonify({"error": "Subject and message are required."}), 400

    ok, detail = send_smtp(
        recipient.strip(),
        subject,
        body,
        sender_name,
        sender_email,
        app_password,
        html_mode,
    )

    result = {
        "email": recipient.strip(),
        "status": "sent" if ok else "failed",
        "detail": detail,
    }

    return jsonify({
        "total": 1,
        "sent": int(ok),
        "failed": int(not ok),
        "results": [result],
        "delaySeconds": MAIL_GAP_SMS,
    })

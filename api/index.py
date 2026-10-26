import json
import os
import re
import random
import ssl
import smtplib
import time
import urllib.parse
import urllib.request
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
app.secret_key = SESSION_SECRET or ""
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("VERCEL", "").lower() == "1"

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip() or "smtp.gmail.com"

try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
except ValueError:
    SMTP_PORT = 587

# Delay is controlled by MAIL_GAP_SECONDS in Vercel Environment Variables.
try:
    MAIL_GAP_SECONDS = max(
        0.0,
        min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 60.0)
    )
except ValueError:
    MAIL_GAP_SECONDS = 1.0

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
TURNSTILE_ENABLED = bool(TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def verify_turnstile(token, remote_ip=None):
    """Verify Cloudflare Turnstile when both keys are configured."""
    if not TURNSTILE_ENABLED:
        return True, None

    if not token:
        return False, "Please complete the security verification and try again."

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(payload).encode("utf-8")

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))

        if result.get("success") is True:
            return True, None

        return False, "Security verification failed. Refresh and try again."

    except Exception:
        app.logger.exception("Turnstile verification request failed")
        return False, "Security verification is temporarily unavailable. Try again later."


def expand_spintax(text):
    """Expand simple Spintax, e.g. {Hello|Hi|Hey}. Nested forms are unsupported."""
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
    body = expand_spintax(body)
    subject = expand_spintax(subject)

    message = EmailMessage()
    message["From"] = formataddr((sender_name or sender_email, sender_email))
    message["To"] = to_email
    message["Subject"] = subject

    if html_mode:
        message.set_content(
            "This message contains HTML content. Please view it in an HTML-capable email client."
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
        return False, "Login failed. Check Gmail address and Google App Password."

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
            error = "Set LOGIN_PASSWORD in Vercel Environment Variables first."
        elif not SESSION_SECRET:
            error = "Set a strong SESSION_SECRET in Vercel Environment Variables first."
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

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY if TURNSTILE_ENABLED else "",
    )


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

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

    verified, verify_error = verify_turnstile(
        str(data.get("turnstileToken", "")),
        request.remote_addr,
    )

    if not verified:
        return jsonify({"error": verify_error}), 400

    if not EMAIL_RE.fullmatch(sender_email):
        return jsonify({"error": "Enter a valid Gmail address."}), 400

    if not app_password:
        return jsonify({"error": "Enter your Google App Password."}), 400

    if not isinstance(recipients, list):
        return jsonify({"error": "Recipients must be a list."}), 400

    clean_recipients = []
    seen = set()

    for item in recipients:
        if isinstance(item, str):
            address = item.strip()
            normalized = address.lower()

            if EMAIL_RE.fullmatch(address) and normalized not in seen:
                seen.add(normalized)
                clean_recipients.append(address)

    if not clean_recipients:
        return jsonify({"error": "No valid recipient addresses found."}), 400

    if len(clean_recipients) > 25:
        return jsonify({"error": "Maximum 25 recipients per batch."}), 400

    if not subject or not body:
        return jsonify({"error": "Subject and message are required."}), 400

    results = []

    for i, recipient in enumerate(clean_recipients):
        ok, detail = send_smtp(
            recipient,
            subject,
            body,
            sender_name,
            sender_email,
            app_password,
            html_mode,
        )

        results.append({
            "email": recipient,
            "status": "sent" if ok else "failed",
            "detail": detail,
        })

        if i < len(clean_recipients) - 1 and MAIL_GAP_SECONDS > 0:
            time.sleep(MAIL_GAP_SECONDS)

    sent = sum(item["status"] == "sent" for item in results)

    return jsonify({
        "total": len(results),
        "sent": sent,
        "failed": len(results) - sent,
        "results": results,
    })

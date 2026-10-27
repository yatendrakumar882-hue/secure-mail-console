```python
import os
import re
import ssl
import random
import smtplib
import logging

from email.message import EmailMessage
from email.utils import formataddr

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
)

# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

# Do not use a random per-instance secret: it invalidates sessions
# whenever a serverless instance changes.
if len(SESSION_SECRET) < 32:
    app.logger.error(
        "SESSION_SECRET is missing or shorter than 32 characters."
    )

app.secret_key = SESSION_SECRET or None

app.config.update(
    MAX_CONTENT_LENGTH=1_000_000,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("VERCEL")),
)

# --------------------------------------------------
# SMTP SETTINGS
# --------------------------------------------------

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()

try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
except (ValueError, TypeError):
    SMTP_PORT = 465

try:
    MAIL_GAP_MS = max(
        0,
        min(int(os.environ.get("MAIL_GAP_MS", "500")), 60000),
    )
except (ValueError, TypeError):
    MAIL_GAP_MS = 500

SMTP_TIMEOUT = 20
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def valid_email(value):
    return (
        isinstance(value, str)
        and bool(EMAIL_RE.fullmatch(value.strip()))
    )


def expand_spintax(text):
    pattern = r"\{([^{}|]+(?:\|[^{}|]+)+)\}"
    return re.sub(
        pattern,
        lambda match: random.choice(match.group(1).split("|")),
        text,
    )


def is_logged_in():
    return session.get("logged_in") is True


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

    message["From"] = formataddr(
        (sender_name or sender_email, sender_email)
    )
    message["To"] = to_email
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
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT,
                context=context,
            ) as server:
                server.login(sender_email, app_password)
                refused = server.send_message(message)
        else:
            with smtplib.SMTP(
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT,
            ) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(sender_email, app_password)
                refused = server.send_message(message)

        if refused:
            return False, "Recipient rejected by SMTP server."

        return True, (
            "SMTP accepted the message. "
            "Inbox placement is not guaranteed."
        )

    except smtplib.SMTPAuthenticationError:
        return False, (
            "Gmail authentication failed. Check the sender address "
            "and Google App Password."
        )

    except smtplib.SMTPRecipientsRefused:
        return False, "Recipient rejected by SMTP."

    except smtplib.SMTPDataError as exc:
        return False, f"SMTP rejected the message (code {exc.smtp_code})."

    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        # Avoid logging passwords or message contents.
        app.logger.warning(
            "SMTP error type=%s recipient=%s",
            type(exc).__name__,
            to_email,
        )
        return False, f"SMTP connection or delivery error ({type(exc).__name__})."

    except Exception:
        app.logger.exception("Unexpected error while sending email.")
        return False, "Unexpected sending error. Check Runtime Logs."


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request is too large."}), 413


@app.errorhandler(500)
def internal_server_error(_error):
    app.logger.exception("Unhandled application error.")
    return jsonify({
        "error": "Internal server error. Check Vercel Runtime Logs."
    }), 500


# --------------------------------------------------
# HEALTH CHECK
# --------------------------------------------------

@app.get("/health")
def health():
    return jsonify({"status": "ok"})


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if not LOGIN_PASSWORD:
        error = "LOGIN_PASSWORD is not configured in Vercel."
    elif len(SESSION_SECRET) < 32:
        error = (
            "SESSION_SECRET must be configured with at least "
            "32 characters in Vercel."
        )

    if request.method == "POST" and error is None:
        supplied_password = request.form.get("password", "")

        if supplied_password == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("index"))

        error = "Incorrect password."

    return render_template("login.html", error=error)


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------
# MAIN PAGE
# --------------------------------------------------

@app.get("/")
def index():
    if not SESSION_SECRET or not LOGIN_PASSWORD:
        return (
            "Application configuration is incomplete. "
            "Check SESSION_SECRET and LOGIN_PASSWORD in Vercel.",
            500,
        )

    if not is_logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


# --------------------------------------------------
# SEND ONE RECIPIENT
# --------------------------------------------------

@app.post("/send-batch")
def send_batch():
    # Validate configuration before accessing session.
    if len(SESSION_SECRET) < 32:
        return jsonify({
            "error": "Configure SESSION_SECRET with at least 32 characters."
        }), 500

    if not LOGIN_PASSWORD:
        return jsonify({
            "error": "Configure LOGIN_PASSWORD in Vercel."
        }), 500

    if not is_logged_in():
        return jsonify({
            "error": "Your session expired. Please sign in again."
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    recipients = data.get("recipients")
    sender_email = str(data.get("senderEmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    sender_name = str(data.get("senderName", "")).strip()[:100]
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    if data.get("consentConfirmed") is not True:
        return jsonify({
            "error": "Confirm recipient permission before sending."
        }), 400

    if not valid_email(sender_email):
        return jsonify({"error": "Invalid sender email address."}), 400

    if not sender_email.lower().endswith("@gmail.com"):
        return jsonify({
            "error": "Sender address must end with @gmail.com."
        }), 400

    if not app_password:
        return jsonify({"error": "Google App Password is required."}), 400

    if not isinstance(recipients, list) or len(recipients) != 1:
        return jsonify({
            "error": "Send one recipient per request for live progress."
        }), 400

    recipient = recipients[0]

    if not valid_email(recipient):
        return jsonify({"error": "Invalid recipient email address."}), 400

    recipient = recipient.strip()

    if not subject:
        return jsonify({"error": "Email subject is required."}), 400

    if not body:
        return jsonify({"error": "Message body is required."}), 400

    if len(subject) > 200:
        return jsonify({"error": "Email subject is too long."}), 400

    if len(body) > 500_000:
        return jsonify({"error": "Message body is too large."}), 413

    success, detail = send_smtp(
        to_email=recipient,
        subject=subject,
        body=body,
        sender_name=sender_name,
        sender_email=sender_email,
        app_password=app_password,
        html_mode=html_mode,
    )

    result = {
        "email": recipient,
        "status": "sent" if success else "failed",
        "detail": detail,
    }

    return jsonify({
        "total": 1,
        "sent": 1 if success else 0,
        "failed": 0 if success else 1,
        "results": [result],
        "delayMs": MAIL_GAP_MS,
    })


# Vercel Python runtime entry point.
application = app
```

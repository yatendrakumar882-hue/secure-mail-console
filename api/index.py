```python
import os
import re
import ssl
import random
import smtplib
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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

# --------------------------------------------------
# SECURITY CONFIGURATION
# --------------------------------------------------

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

app.secret_key = SESSION_SECRET

app.config["MAX_CONTENT_LENGTH"] = 1_000_000
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = bool(os.environ.get("VERCEL"))

# --------------------------------------------------
# SMTP CONFIGURATION
# --------------------------------------------------

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()

try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
except (ValueError, TypeError):
    SMTP_PORT = 465

# Sending delay in milliseconds.
# Example: 500 = 0.5 seconds.
try:
    MAIL_GAP_MS = max(
        0,
        min(
            int(os.environ.get("MAIL_GAP_MS", "500")),
            60000,
        ),
    )
except (ValueError, TypeError):
    MAIL_GAP_MS = 500

MAX_BATCH_SIZE = 5
MAX_RECIPIENTS = 25
SMTP_TIMEOUT = 20

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------
# COMMON HELPERS
# --------------------------------------------------

def logged_in():
    return session.get("logged_in") is True


def valid_email(value):
    return isinstance(value, str) and bool(
        EMAIL_RE.fullmatch(value.strip())
    )


def expand_spintax(text):
    """
    Example:
    {Hello|Hi|Hey} there
    """
    pattern = r"\{([^{}|]+(?:\|[^{}|]+)+)\}"

    return re.sub(
        pattern,
        lambda match: random.choice(match.group(1).split("|")),
        text,
    )


# --------------------------------------------------
# GMAIL SMTP SENDING
# --------------------------------------------------

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

    message["From"] = formataddr(
        (sender_name or sender_email, sender_email)
    )
    message["To"] = to_email
    message["Subject"] = subject

    if html_mode:
        message.set_content(
            "Please view this message in an HTML-capable email client."
        )
        message.add_alternative(body, subtype="html")
    else:
        message.set_content(body)

    context = ssl.create_default_context()

    try:
        if SMTP_PORT == 465:
            # SSL connection
            with smtplib.SMTP_SSL(
                SMTP_HOST,
                SMTP_PORT,
                timeout=SMTP_TIMEOUT,
                context=context,
            ) as server:
                server.login(sender_email, app_password)
                refused = server.send_message(message)

        else:
            # STARTTLS connection
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

        return (
            True,
            "SMTP accepted the message. Inbox placement is not guaranteed.",
        )

    except smtplib.SMTPAuthenticationError:
        return (
            False,
            "Gmail authentication failed. Check the Gmail address and App Password.",
        )

    except smtplib.SMTPRecipientsRefused:
        return False, "Recipient address was rejected by SMTP."

    except smtplib.SMTPDataError as exc:
        return False, f"SMTP rejected the message (code {exc.smtp_code})."

    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        return False, f"SMTP error: {str(exc)[:160]}"

    except Exception:
        app.logger.exception("Unexpected email sending error")
        return False, "Unexpected sending error. Check server logs."


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

    if request.method == "POST":
        if not LOGIN_PASSWORD:
            error = "Set LOGIN_PASSWORD in Vercel Environment Variables."

        elif len(SESSION_SECRET) < 32:
            error = (
                "SESSION_SECRET must contain at least "
                "32 characters."
            )

        elif request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            session.permanent = False

            return redirect(url_for("index"))

        else:
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
    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


# --------------------------------------------------
# SEND EMAIL ENDPOINT
# --------------------------------------------------

@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({
            "error": "Your session expired. Please sign in again."
        }), 401

    if len(SESSION_SECRET) < 32:
        return jsonify({
            "error": "Configure a strong SESSION_SECRET."
        }), 500

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    recipients = data.get("recipients")
    sender_email = str(data.get("senderEmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    sender_name = str(data.get("senderName", "")).strip()[:100]
    subject = str(data.get("subject", "")).strip()[:200]
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    # Explicit recipient permission confirmation.
    if data.get("consentConfirmed") is not True:
        return jsonify({
            "error": "Confirm recipient permission before sending."
        }), 400

    if not valid_email(sender_email):
        return jsonify({
            "error": "Enter a valid sender email address."
        }), 400

    if not sender_email.lower().endswith("@gmail.com"):
        return jsonify({
            "error": "Use a Gmail address ending in @gmail.com."
        }), 400

    if not app_password:
        return jsonify({
            "error": "Enter your Google App Password."
        }), 400

    if not isinstance(recipients, list):
        return jsonify({
            "error": "Recipients must be a list."
        }), 400

    # This endpoint intentionally processes one recipient per request.
    # The frontend groups recipients into batches of five and updates
    # the Progress Monitor after each individual response.
    if len(recipients) != 1:
        return jsonify({
            "error": "Send one recipient per request for live progress."
        }), 400

    recipient = recipients[0]

    if not valid_email(recipient):
        return jsonify({
            "error": "Enter a valid recipient email address."
        }), 400

    recipient = recipient.strip()

    if not subject:
        return jsonify({"error": "Email subject is required."}), 400

    if not body:
        return jsonify({"error": "Message body is required."}), 400

    if len(subject) > 200:
        return jsonify({"error": "Subject is too long."}), 400

    if len(body) > 500_000:
        return jsonify({"error": "Message body is too large."}), 413

    # Process exactly one recipient so the browser can update its
    # counters when the SMTP result for this recipient returns.
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


# --------------------------------------------------
# VERCEL WSGI ENTRY POINT
# --------------------------------------------------

application = app
```

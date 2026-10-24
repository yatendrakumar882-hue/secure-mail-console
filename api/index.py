
import os
import re
import ssl
import json
import hmac
import html
import smtplib
from pathlib import Path
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate

from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    jsonify,
    session,
    Response,
)

# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)

# Vercel Python runtime entry point
handler = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "SESSION_SECRET must be configured in Vercel "
        "and contain at least 32 characters."
    )

if not LOGIN_PASSWORD:
    raise RuntimeError(
        "LOGIN_PASSWORD must be configured in Vercel."
    )

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    MAX_CONTENT_LENGTH=1_000_000,
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 25

# Conservative concurrency; increasing this does not guarantee
# better inbox placement and may trigger Gmail limits.
MAX_PARALLEL_SENDS = 2

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def clean(value, limit=250):
    """Clean header values to prevent newline/header injection."""
    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()[:limit]
    )


def valid_email(value):
    if not isinstance(value, str):
        return False

    value = value.strip()

    return (
        len(value) <= 254
        and bool(EMAIL_RE.fullmatch(value))
    )


def logged_in():
    return session.get("authenticated") is True


def error_response(message, status=400):
    return jsonify({
        "success": False,
        "message": message,
    }), status


def event_line(payload):
    """Emit one newline-delimited JSON event for the dashboard."""
    return json.dumps(payload, ensure_ascii=False) + "\n"


def html_to_text(value):
    """Create a simple plain-text alternative from HTML."""
    value = re.sub(
        r"(?i)<\s*br\s*/?\s*>",
        "\n",
        value,
    )

    value = re.sub(
        r"(?i)</\s*(p|div|li|h[1-6])\s*>",
        "\n",
        value,
    )

    value = re.sub(r"<[^>]*>", " ", value)
    value = html.unescape(value)

    return re.sub(r"\n{3,}", "\n\n", value).strip()


def normalize_recipient(item):
    """
    Accept either an email string or a dictionary:
    {"email": "person@example.com", "name": "Person"}
    """
    if isinstance(item, str):
        item = {"email": item}

    if not isinstance(item, dict):
        return None

    address = str(item.get("email", "")).strip().lower()

    if not valid_email(address):
        return None

    return {
        "email": address,
        "name": clean(item.get("name", ""), 150),
        "hi": clean(item.get("hi", ""), 100),
        "hello": clean(item.get("hello", ""), 100),
        "thanks": clean(item.get("thanks", ""), 100),
        "ref_code": clean(item.get("ref_code", ""), 100),
    }


def personalize(value, recipient):
    """Replace supported personalization placeholders."""
    result = str(value or "")

    replacements = {
        "name": recipient.get("name", ""),
        "email": recipient.get("email", ""),
        "hi": recipient.get("hi", ""),
        "hello": recipient.get("hello", ""),
        "thanks": recipient.get("thanks", ""),
        "ref_code": recipient.get("ref_code", ""),
    }

    for key, replacement in replacements.items():
        result = result.replace(
            "{{" + key + "}}",
            replacement,
        )

    return result


# --------------------------------------------------
# GMAIL SMTP SENDING
# --------------------------------------------------

def send_one(
    gmail,
    app_password,
    sender_name,
    subject,
    body,
    is_html,
    recipient,
):
    """
    Send one email through Gmail SMTP over SSL.
    A successful return means Gmail accepted the message,
    not that the recipient's Inbox placement is confirmed.
    """
    message = EmailMessage()

    personalized_subject = clean(
        personalize(subject, recipient),
        250,
    )

    personalized_body = personalize(body, recipient)

    message["Subject"] = personalized_subject
    message["From"] = formataddr(
        (clean(sender_name, 100), gmail)
    )
    message["To"] = recipient["email"]
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    if is_html:
        plain_body = html_to_text(personalized_body)

        if not plain_body:
            plain_body = (
                "This email contains an HTML message. "
                "Please use an HTML-capable email client."
            )

        message.set_content(plain_body)
        message.add_alternative(
            personalized_body,
            subtype="html",
        )
    else:
        message.set_content(personalized_body)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT,
    ) as smtp:
        smtp.ehlo()
        smtp.login(
            gmail,
            re.sub(r"\s+", "", app_password),
        )

        refused = smtp.send_message(
            message,
            from_addr=gmail,
            to_addrs=[recipient["email"]],
        )

        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)

    return True


# --------------------------------------------------
# LOGIN / LOGOUT
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template(
            "login.html",
            error=None,
        )

    submitted_password = str(
        request.form.get("password", "")
    )

    if not hmac.compare_digest(
        submitted_password,
        LOGIN_PASSWORD,
    ):
        return render_template(
            "login.html",
            error="Incorrect password.",
        ), 401

    session.clear()
    session.permanent = True
    session["authenticated"] = True

    return redirect(url_for("home"))


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
def home():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "smtp": "Gmail SMTP over SSL",
        "max_recipients": MAX_RECIPIENTS,
        "max_parallel_sends": MAX_PARALLEL_SENDS,
    })


@app.route("/favicon.ico")
def favicon():
    return Response("", status=204)


# --------------------------------------------------
# SEND BATCH
# --------------------------------------------------

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not logged_in():
        return jsonify({
            "success": False,
            "message": "Your session expired. Please log in again.",
            "login_required": True,
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response(
            "Invalid request. Expected JSON data."
        )

    sender_name = clean(
        data.get("sender_name", ""),
        100,
    )

    gmail = clean(
        data.get("gmail", ""),
        254,
    ).lower()

    app_password = str(
        data.get("app_password", "")
    ).strip()

    subject = clean(
        data.get("subject", ""),
        250,
    )

    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    incoming = data.get("recipients", [])

    # Require an explicit recipient-consent confirmation.
    if data.get("consent_confirmed") is not True:
        return error_response(
            "Confirm that recipients agreed to receive this email."
        )

    if not sender_name:
        return error_response("Sender name is required.")

    if (
        not valid_email(gmail)
        or not gmail.endswith("@gmail.com")
    ):
        return error_response(
            "Enter a valid @gmail.com sender address."
        )

    if not app_password:
        return error_response(
            "Enter your Google App Password."
        )

    if not subject:
        return error_response("Email subject is required.")

    if not body.strip():
        return error_response("Email message body is required.")

    if len(body) > 100_000:
        return error_response(
            "Message body is too large. Please shorten it."
        )

    if not isinstance(incoming, list):
        return error_response(
            "Recipients must be provided as a list."
        )

    recipients = []
    seen = set()
    invalid_count = 0

    for item in incoming:
        recipient = normalize_recipient(item)

        if recipient is None:
            invalid_count += 1
            continue

        address = recipient["email"]

        # Prevent sending twice to the same address in one batch.
        if address in seen:
            continue

        seen.add(address)
        recipients.append(recipient)

    if not recipients:
        return error_response(
            "No valid recipient addresses were found."
        )

    if len(recipients) > MAX_RECIPIENTS:
        return error_response(
            f"Maximum {MAX_RECIPIENTS} unique recipients per batch."
        )

    def generate_events():
        total = len(recipients)
        sent = 0
        failed = 0

        yield event_line({
            "type": "start",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": total,
            "invalid_skipped": invalid_count,
        })

        with ThreadPoolExecutor(
            max_workers=min(
                MAX_PARALLEL_SENDS,
                total,
            )
        ) as executor:
            jobs = {
                executor.submit(
                    send_one,
                    gmail,
                    app_password,
                    sender_name,
                    subject,
                    body,
                    is_html,
                    recipient,
                ): recipient
                for recipient in recipients
            }

            for future in as_completed(jobs):
                recipient = jobs[future]
                result = "sent"
                detail = "Gmail accepted the message."

                try:
                    future.result()
                    sent += 1

                except smtplib.SMTPAuthenticationError:
                    failed += 1
                    result = "failed"
                    detail = (
                        "Gmail authentication failed. "
                        "Check the Gmail address and App Password."
                    )

                except smtplib.SMTPRecipientsRefused:
                    failed += 1
                    result = "failed"
                    detail = (
                        "Gmail refused this recipient address."
                    )

                except smtplib.SMTPResponseException as exc:
                    failed += 1
                    result = "failed"
                    detail = (
                        f"SMTP error {exc.smtp_code}. "
                        "Check Gmail limits and SMTP response."
                    )

                except (
                    smtplib.SMTPException,
                    TimeoutError,
                    OSError,
                ) as exc:
                    failed += 1
                    result = "failed"
                    detail = (
                        "SMTP/network error: "
                        + str(exc)[:160]
                    )

                except Exception:
                    failed += 1
                    result = "failed"
                    detail = (
                        "Unexpected sending error. "
                        "Check Vercel function logs."
                    )

                yield event_line({
                    "type": "progress",
                    "recipient": recipient["email"],
                    "result": result,
                    "message": detail,
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": total - sent - failed,
                })

        yield event_line({
            "type": "complete",
            "success": failed == 0,
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0,
            "message": (
                "Sending attempt finished. Gmail SMTP acceptance "
                "does not confirm Inbox delivery."
            ),
        })

    response = Response(
        generate_events(),
        content_type="application/x-ndjson; charset=utf-8",
    )

    response.headers["Cache-Control"] = (
        "no-store, no-cache, no-transform"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Accel-Buffering"] = "no"

    return response


# --------------------------------------------------
# LOCAL DEVELOPMENT
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )

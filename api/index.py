
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
# Flask / Vercel configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)
handler = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "Set SESSION_SECRET in Vercel to a random secret "
        "containing at least 32 characters."
    )

if not LOGIN_PASSWORD:
    raise RuntimeError("Set LOGIN_PASSWORD in Vercel.")

app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    MAX_CONTENT_LENGTH=1_000_000,
)

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

MAX_RECIPIENTS = 25

# Conservative concurrency for Gmail SMTP.
# Increasing concurrency does not guarantee better inbox placement.
MAX_PARALLEL_SENDS = 2

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


# --------------------------------------------------
# Helpers
# --------------------------------------------------

def clean(value, limit=250):
    """Clean email header values and limit their length."""
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
    """Return one newline-delimited JSON event."""
    return json.dumps(payload, ensure_ascii=False) + "\n"


def html_to_text(value):
    """Generate a basic readable plain-text alternative."""
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
    if isinstance(item, str):
        item = {"email": item}

    if not isinstance(item, dict):
        return None

    address = str(item.get("email", "")).strip().lower()

    if not valid_email(address):
        return None

    return {
        "email": address,
        **{
            key: clean(item.get(key, ""), 150)
            for key in (
                "name",
                "hi",
                "hello",
                "thanks",
                "ref_code",
            )
        },
    }


def personalize(value, recipient):
    result = str(value or "")

    for key in (
        "hi",
        "hello",
        "thanks",
        "name",
        "email",
        "ref_code",
    ):
        result = result.replace(
            "{{" + key + "}}",
            recipient.get(key, ""),
        )

    return result


# --------------------------------------------------
# Gmail SMTP
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
    message = EmailMessage()

    message["Subject"] = clean(
        personalize(subject, recipient),
        250,
    )
    message["From"] = formataddr(
        (clean(sender_name, 100), gmail)
    )
    message["To"] = recipient["email"]
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    content = personalize(body, recipient)

    if is_html:
        plain_text = html_to_text(content)

        if not plain_text:
            plain_text = (
                "Please view this message in an "
                "HTML-compatible email client."
            )

        message.set_content(plain_text)
        message.add_alternative(content, subtype="html")
    else:
        message.set_content(content)

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT,
    ) as smtp:
        smtp.ehlo()

        # Gmail App Password; remove spaces only.
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
# Login / logout
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("login.html", error=None)

    submitted = str(request.form.get("password", ""))

    if not hmac.compare_digest(submitted, LOGIN_PASSWORD):
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


@app.route("/")
def home():
    if not logged_in():
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "smtp": "Gmail SMTP over SSL",
        "max_recipients": MAX_RECIPIENTS,
        "parallel_sends": MAX_PARALLEL_SENDS,
    })


@app.route("/favicon.ico")
def favicon():
    return Response("", status=204)


@app.route("/sw.js")
def service_worker():
    return Response("", mimetype="application/javascript")


# --------------------------------------------------
# Send batch with live progress
# --------------------------------------------------

@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not logged_in():
        return jsonify({
            "success": False,
            "message": "Please log in again.",
            "login_required": True,
        }), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return error_response("Invalid JSON request.")

    sender_name = clean(data.get("sender_name", ""), 100)
    gmail = clean(data.get("gmail", ""), 254).lower()
    app_password = str(data.get("app_password", "")).strip()
    subject = clean(data.get("subject", ""), 250)
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    incoming = data.get("recipients", [])

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
        return error_response("Gmail App Password is required.")

    if not subject:
        return error_response("Email subject is required.")

    if not body.strip():
        return error_response("Email body is required.")

    if len(body) > 100_000:
        return error_response("Email body is too large.")

    if not isinstance(incoming, list):
        return error_response("Recipients must be a list.")

    if data.get("consent_confirmed") is not True:
        return error_response(
            "Confirm that recipients agreed to receive this email."
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

        if address not in seen:
            seen.add(address)
            recipients.append(recipient)

    if not recipients:
        return error_response("No valid recipients found.")

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
            max_workers=min(MAX_PARALLEL_SENDS, total)
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
                        "Check the address and App Password."
                    )

                except smtplib.SMTPRecipientsRefused:
                    failed += 1
                    result = "failed"
                    detail = "Gmail refused this recipient."

                except smtplib.SMTPResponseException as exc:
                    failed += 1
                    result = "failed"
                    detail = (
                        f"SMTP error {exc.smtp_code}. "
                        "Check Gmail's response and sending limits."
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
                        + str(exc)[:150]
                    )

                except Exception:
                    failed += 1
                    result = "failed"
                    detail = (
                        "Unexpected error. Check Vercel logs."
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


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=False,
    )

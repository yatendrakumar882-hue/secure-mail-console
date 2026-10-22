
import os
import re
import json
import ssl
import time
import hmac
import html
import secrets
import smtplib
import urllib.parse
import urllib.request

from pathlib import Path
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate

from flask import (
    Flask, request, render_template, redirect, url_for,
    jsonify, session, Response, stream_with_context
)

# ---------------------------------------------------------
# APP CONFIG
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)
handler = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()

if not SESSION_SECRET or len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "Set SESSION_SECRET in Vercel to a long random secret (32+ characters)."
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
SMTP_TIMEOUT = 20

MAX_RECIPIENTS = 25

# Sequential sending avoids opening several SMTP sessions at once.
# This is not a guarantee of inbox placement.
SEND_DELAY_SECONDS = 2.0

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------

def clean_header(value, limit=250):
    """Prevent CR/LF header injection."""
    value = str(value or "").replace("\r", " ").replace("\n", " ")
    return value.strip()[:limit]


def valid_email(value):
    if not isinstance(value, str):
        return False
    value = value.strip()
    return len(value) <= 254 and bool(EMAIL_RE.fullmatch(value))


def logged_in():
    return session.get("authenticated") is True


def json_error(message, status=400):
    return jsonify({"success": False, "message": message}), status


def ndjson_event(event):
    return json.dumps(event, ensure_ascii=False) + "\n"


def verify_turnstile(token, remote_ip=None):
    if not TURNSTILE_SECRET_KEY:
        return False, "TURNSTILE_SECRET_KEY is not configured."

    if not token:
        return False, "Complete the Cloudflare verification first."

    fields = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }
    if remote_ip:
        fields["remoteip"] = remote_ip

    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
        if result.get("success") is True:
            return True, None
        return False, "Cloudflare verification failed. Refresh and try again."
    except Exception:
        return False, "Could not verify Cloudflare. Please try again."


def html_to_text(value):
    """Create a readable plain-text alternative for HTML email."""
    value = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", value)
    value = re.sub(r"(?i)</\s*(p|div|li|h[1-6])\s*>", "\n", value)
    value = re.sub(r"<[^>]*>", " ", value)
    value = html.unescape(value)
    value = re.sub(r"[ \t]+\n", "\n", value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


def normalize_recipient(item):
    if isinstance(item, str):
        item = {"email": item}
    if not isinstance(item, dict):
        return None

    email = str(item.get("email", "")).strip().lower()
    if not valid_email(email):
        return None

    result = {"email": email}
    for key in ("name", "hi", "hello", "thanks", "ref_code"):
        result[key] = clean_header(item.get(key, ""), 200)
    return result


def personalize(value, recipient):
    result = str(value or "")
    for key in ("hi", "hello", "thanks", "name", "email", "ref_code"):
        result = result.replace(
            "{{" + key + "}}",
            str(recipient.get(key, "") or ""),
        )
    return result


def build_message(gmail, sender_name, subject, body, is_html, recipient):
    msg = EmailMessage()
    msg["Subject"] = clean_header(personalize(subject, recipient), 250)
    msg["From"] = formataddr((clean_header(sender_name), gmail))
    msg["To"] = recipient["email"]
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    personalized_body = personalize(body, recipient)

    if is_html:
        msg.set_content(html_to_text(personalized_body) or "Please view this message in an HTML-capable email client.")
        msg.add_alternative(personalized_body, subtype="html")
    else:
        msg.set_content(personalized_body)

    return msg


def send_one(gmail, app_password, sender_name, subject, body, is_html, recipient):
    if SEND_DELAY_SECONDS:
        time.sleep(SEND_DELAY_SECONDS)

    message = build_message(
        gmail, sender_name, subject, body, is_html, recipient
    )

    # Gmail App Passwords are commonly shown with spaces.
    clean_password = re.sub(r"\s+", "", app_password)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(
        SMTP_HOST, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT
    ) as smtp:
        smtp.ehlo()
        smtp.login(gmail, clean_password)
        refused = smtp.send_message(
            message,
            from_addr=gmail,
            to_addrs=[recipient["email"]],
        )
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)

    # "sent" means Gmail accepted the message for sending.
    # It does not confirm Inbox placement or final delivery.


# ---------------------------------------------------------
# BASIC ROUTES
# ---------------------------------------------------------

@app.route("/sw.js")
def service_worker():
    return Response("", mimetype="application/javascript")


@app.route("/favicon.ico")
def favicon():
    return Response("", status=204)


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template(
            "login.html",
            error=None,
            turnstile_site_key=TURNSTILE_SITE_KEY,
        )

    password = str(request.form.get("password", ""))
    if not hmac.compare_digest(password, LOGIN_PASSWORD):
        return render_template(
            "login.html",
            error="Incorrect password.",
            turnstile_site_key=TURNSTILE_SITE_KEY,
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

    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "mailer": "Gmail SMTP",
        "max_recipients": MAX_RECIPIENTS,
        "sending_mode": "sequential",
        "authenticated": logged_in(),
    })


# ---------------------------------------------------------
# SEND BATCH
# Compatible with a dashboard sending JSON and reading
# newline-delimited JSON events.
# ---------------------------------------------------------

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
        return json_error("Invalid JSON request.")

    sender_name = clean_header(data.get("sender_name", ""))
    gmail = clean_header(data.get("gmail", ""), 254).lower()
    app_password = str(data.get("app_password", "")).strip()
    subject = clean_header(data.get("subject", ""), 250)
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    recipients_input = data.get("recipients", [])
    token = str(data.get("turnstile_token", "")).strip()

    if not sender_name:
        return json_error("Sender name is required.")
    if not valid_email(gmail) or not gmail.endswith("@gmail.com"):
        return json_error("Enter a valid @gmail.com sender address.")
    if not app_password:
        return json_error("Gmail App Password is required.")
    if not subject:
        return json_error("Subject is required.")
    if not body.strip():
        return json_error("Email body is required.")
    if len(body) > 100_000:
        return json_error("Email body is too large.")
    if not isinstance(recipients_input, list):
        return json_error("Recipients must be a list.")

    # Do not allow the checkbox to be the only proof of consent:
    # the operator must only include recipients who have permission
    # to receive this type of message.
    if data.get("consent_confirmed") is not True:
        return json_error(
            "Confirm that these recipients have permission to receive this email."
        )

    recipients = []
    seen = set()
    invalid_count = 0

    for item in recipients_input:
        recipient = normalize_recipient(item)
        if recipient is None:
            invalid_count += 1
            continue
        if recipient["email"] in seen:
            continue
        seen.add(recipient["email"])
        recipients.append(recipient)

    if len(recipients) > MAX_RECIPIENTS:
        return json_error(
            f"Maximum {MAX_RECIPIENTS} unique valid recipients are allowed per batch."
        )
    if not recipients:
        return json_error("No valid recipients were found.")

    # Avoid trusting arbitrary X-Forwarded-For values for security.
    remote_ip = request.remote_addr
    verified, error = verify_turnstile(token, remote_ip)
    if not verified:
        return json_error(error or "Cloudflare verification failed.", 403)

    @stream_with_context
    def generate():
        total = len(recipients)
        sent = 0
        failed = 0

        yield ndjson_event({
            "type": "start",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": total,
            "invalid_skipped": invalid_count,
        })

        for recipient in recipients:
            try:
                send_one(
                    gmail, app_password, sender_name, subject,
                    body, is_html, recipient
                )
                sent += 1
                event = {
                    "type": "progress",
                    "email": recipient["email"],
                    "result": "sent",
                }

            except smtplib.SMTPAuthenticationError:
                failed += 1
                event = {
                    "type": "progress",
                    "email": recipient["email"],
                    "result": "failed",
                    "error": "Gmail authentication failed. Check the sender address and App Password.",
                }

            except smtplib.SMTPRecipientsRefused:
                failed += 1
                event = {
                    "type": "progress",
                    "email": recipient["email"],
                    "result": "failed",
                    "error": "Gmail refused this recipient.",
                }

            except smtplib.SMTPResponseException as exc:
                failed += 1
                # Keep the SMTP response code for diagnosis.
                event = {
                    "type": "progress",
                    "email": recipient["email"],
                    "result": "failed",
                    "error": f"SMTP error {exc.smtp_code}: {str(exc.smtp_error)[:250]}",
                }

            except (smtplib.SMTPException, TimeoutError, OSError) as exc:
                failed += 1
                event = {
                    "type": "progress",
                    "email": recipient["email"],
                    "result": "failed",
                    "error": f"SMTP/network error: {str(exc)[:250]}",
                }

            except Exception:
                failed += 1
                event = {
                    "type": "progress",
                    "email": recipient["email"],
                    "result": "failed",
                    "error": "Unexpected sending error. Check server logs.",
                }

            event.update({
                "total": total,
                "sent": sent,
                "failed": failed,
                "remaining": total - sent - failed,
            })
            yield ndjson_event(event)

        yield ndjson_event({
            "type": "complete",
            "success": failed == 0,
            "message": "Sending run finished.",
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": total - sent - failed,
        })

    response = Response(
        generate(),
        content_type="application/x-ndjson; charset=utf-8",
    )
    response.headers["Cache-Control"] = "no-store, no-cache, no-transform"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Accel-Buffering"] = "no"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

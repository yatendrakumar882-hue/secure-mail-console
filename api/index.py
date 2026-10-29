"""Flask Gmail SMTP sender for Vercel.

Keeps the original configuration and sending concurrency: Gmail SMTP over SSL,
zero intentional delay, up to six concurrent sends, and 25 unique recipients
per batch. SMTP acceptance does not guarantee placement in the recipient's Inbox.
"""

import os
import re
import ssl
import json
import hmac
import html
import time
import smtplib
from pathlib import Path
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate
from flask import (
    Flask, request, render_template, redirect, url_for, jsonify, session, Response
)

BASE_DIR = Path(__file__).resolve().parent.parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
    static_url_path="/static",
)
# Vercel's Python runtime can discover the WSGI application as `app` or `handler`.
handler = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()
if len(SESSION_SECRET) < 32:
    raise RuntimeError("Set SESSION_SECRET to a random value of at least 32 characters.")
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
SEND_DELAY_SECONDS = 0  # Preserves the uploaded file's intentional delay setting.
MAX_PARALLEL_SENDS = 6  # Preserves the uploaded file's maximum concurrency.
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def clean(value, limit=250):
    """Remove header line breaks and bound user-provided header values."""
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def valid_email(value):
    return (
        isinstance(value, str)
        and len(value.strip()) <= 254
        and bool(EMAIL_RE.fullmatch(value.strip()))
    )


def logged_in():
    return session.get("authenticated") is True


def error(message, status=400):
    return jsonify({"success": False, "message": message}), status


def event_line(data):
    return json.dumps(data, ensure_ascii=False) + "\n"


def html_to_text(value):
    """Create a basic readable plain-text alternative from HTML content."""
    value = str(value or "")
    value = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", value)
    value = re.sub(r"(?i)</\s*(p|div|li|h[1-6]|tr)\s*>", "\n", value)
    value = re.sub(r"(?i)<\s*li\b[^>]*>", "- ", value)
    value = re.sub(r"<[^>]*>", " ", value)
    value = html.unescape(value)
    value = re.sub(r"[ \t\f\v]+", " ", value)
    value = re.sub(r" *\n *", "\n", value)
    return re.sub(r"\n{3,}", "\n\n", value).strip()


def normalize_recipient(item):
    if isinstance(item, str):
        item = {"email": item}
    if not isinstance(item, dict):
        return None
    address = str(item.get("email", "")).strip().lower()
    if not valid_email(address):
        return None
    result = {"email": address}
    for key in ("name", "hi", "hello", "thanks", "ref_code"):
        result[key] = clean(item.get(key, ""), 150)
    return result


def personalize(value, recipient):
    result = str(value or "")
    for key in ("hi", "hello", "thanks", "name", "email", "ref_code"):
        result = result.replace("{{" + key + "}}", recipient.get(key, ""))
    return result


def send_one(gmail, app_password, sender_name, subject, body, is_html, recipient):
    if SEND_DELAY_SECONDS:
        time.sleep(SEND_DELAY_SECONDS)

    msg = EmailMessage()
    msg["Subject"] = clean(personalize(subject, recipient), 250)
    msg["From"] = formataddr((clean(sender_name, 150), gmail))
    msg["To"] = recipient["email"]
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    content = personalize(body, recipient)
    if is_html:
        plain_text = html_to_text(content)
        msg.set_content(plain_text or "Please view this message in an HTML-capable email client.")
        msg.add_alternative(content, subtype="html")
    else:
        msg.set_content(content)

    # Gmail App Password is used only for SMTP authentication; no credentials are logged.
    app_password = re.sub(r"\s+", "", app_password)
    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=ssl.create_default_context(),
        timeout=SMTP_TIMEOUT,
    ) as smtp:
        smtp.ehlo()
        smtp.login(gmail, app_password)
        refused = smtp.send_message(msg, from_addr=gmail, to_addrs=[recipient["email"]])
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("login.html", error=None)
    submitted = str(request.form.get("password", ""))
    if not hmac.compare_digest(submitted, LOGIN_PASSWORD):
        return render_template("login.html", error="Incorrect password."), 401
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
        "smtp": "Gmail SMTP",
        "max_recipients": MAX_RECIPIENTS,
        "send_delay_seconds": SEND_DELAY_SECONDS,
        "max_parallel_sends": MAX_PARALLEL_SENDS,
    })


@app.route("/favicon.ico")
def favicon():
    return Response("", status=204)


@app.route("/sw.js")
def service_worker():
    return Response("", mimetype="application/javascript")


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
        return error("Invalid JSON request.")

    sender_name = clean(data.get("sender_name", ""), 150)
    gmail = clean(data.get("gmail", ""), 254).lower()
    password = str(data.get("app_password", "")).strip()
    subject = clean(data.get("subject", ""), 250)
    body = str(data.get("body", ""))
    is_html = data.get("is_html") is True
    incoming = data.get("recipients", [])

    if not sender_name or not valid_email(gmail) or not gmail.endswith("@gmail.com"):
        return error("Enter a sender name and valid @gmail.com address.")
    if not password or not subject or not body.strip():
        return error("App Password, subject and body are required.")
    if len(body) > 100_000:
        return error("Email body is too large.")
    if not isinstance(incoming, list):
        return error("Recipients must be a list.")
    if data.get("consent_confirmed") is not True:
        return error("Confirm recipients have permission to receive this email.")

    recipients, seen, invalid = [], set(), 0
    for item in incoming:
        recipient = normalize_recipient(item)
        if not recipient:
            invalid += 1
        elif recipient["email"] not in seen:
            seen.add(recipient["email"])
            recipients.append(recipient)

    if not recipients:
        return error("No valid recipients found.")
    if len(recipients) > MAX_RECIPIENTS:
        return error(f"Maximum {MAX_RECIPIENTS} unique recipients per batch.")

    def generate():
        total = len(recipients)
        sent = failed = 0
        yield event_line({
            "type": "start", "total": total, "sent": 0, "failed": 0,
            "remaining": total, "invalid_skipped": invalid,
        })

        with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_SENDS, total)) as pool:
            jobs = {
                pool.submit(
                    send_one, gmail, password, sender_name, subject, body, is_html, recipient
                ): recipient
                for recipient in recipients
            }
            for future in as_completed(jobs):
                recipient = jobs[future]
                try:
                    future.result()
                    sent += 1
                    item = {
                        "type": "progress", "recipient": recipient["email"],
                        "result": "sent",
                    }
                except smtplib.SMTPAuthenticationError:
                    failed += 1
                    item = {
                        "type": "progress", "recipient": recipient["email"],
                        "result": "failed",
                        "error": "Gmail authentication failed. Check the Gmail address and App Password.",
                    }
                except smtplib.SMTPRecipientsRefused:
                    failed += 1
                    item = {
                        "type": "progress", "recipient": recipient["email"],
                        "result": "failed", "error": "Gmail refused this recipient.",
                    }
                except smtplib.SMTPResponseException as exc:
                    failed += 1
                    detail = exc.smtp_error.decode("utf-8", "replace") if isinstance(exc.smtp_error, bytes) else str(exc.smtp_error)
                    item = {
                        "type": "progress", "recipient": recipient["email"],
                        "result": "failed",
                        "error": f"SMTP error {exc.smtp_code}: {detail[:200]}",
                    }
                except (smtplib.SMTPException, TimeoutError, OSError) as exc:
                    failed += 1
                    item = {
                        "type": "progress", "recipient": recipient["email"],
                        "result": "failed", "error": f"SMTP/network error: {str(exc)[:200]}",
                    }
                except Exception as exc:
                    failed += 1
                    app.logger.exception("Unexpected send error for recipient")
                    item = {
                        "type": "progress", "recipient": recipient["email"],
                        "result": "failed",
                        "error": f"Unexpected error ({type(exc).__name__}). Check Vercel logs.",
                    }

                item.update({
                    "total": total, "sent": sent, "failed": failed,
                    "remaining": total - sent - failed,
                })
                yield event_line(item)

        yield event_line({
            "type": "complete", "success": failed == 0,
            "message": "Sending attempt finished. Gmail acceptance does not confirm Inbox delivery.",
            "total": total, "sent": sent, "failed": failed, "remaining": 0,
        })

    response = Response(generate(), content_type="application/x-ndjson; charset=utf-8")
    response.headers["Cache-Control"] = "no-store, no-cache, no-transform"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Accel-Buffering"] = "no"
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

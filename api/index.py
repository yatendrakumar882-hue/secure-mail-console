import os
import re
import ssl
import time
import logging
import smtplib
from email.message import EmailMessage
from email.utils import formataddr

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, Response, stream_with_context
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

# Speed is controlled only in Vercel Environment Variables.
# MAIL_GAP_MS=250 means a 250 millisecond pause between recipients.
try:
    MAIL_GAP_MS = max(0, min(int(os.environ.get("MAIL_GAP_MS", "500")), 60000))
except (TypeError, ValueError):
    MAIL_GAP_MS = 500

SMTP_TIMEOUT = 20
MAX_RECIPIENTS = 25
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app.secret_key = SESSION_SECRET or None
app.config.update(
    MAX_CONTENT_LENGTH=1_000_000,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("VERCEL")),
    PERMANENT_SESSION_LIFETIME=3600,
)


def logged_in():
    return session.get("logged_in") is True


def expand_spintax(value):
    pattern = r"\{([^{}|]+(?:\|[^{}|]+)+)\}"
    return re.sub(
        pattern,
        lambda match: __import__("random").choice(match.group(1).split("|")),
        value,
    )


def make_message(recipient, subject, body, sender_name, sender_email, html_mode):
    message = EmailMessage()
    message["From"] = formataddr((sender_name or sender_email, sender_email))
    message["To"] = recipient
    message["Subject"] = expand_spintax(subject)

    content = expand_spintax(body)
    if html_mode:
        message.set_content("Please view this message in an HTML-capable email client.")
        message.add_alternative(content, subtype="html")
    else:
        message.set_content(content)
    return message


def open_smtp(sender_email, app_password):
    context = ssl.create_default_context()
    if SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(
            SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT, context=context
        )
    elif SMTP_PORT == 587:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT)
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
    else:
        raise ValueError("SMTP_PORT must be 465 (SSL) or 587 (STARTTLS).")

    try:
        server.login(sender_email, app_password)
        return server
    except Exception:
        try:
            server.quit()
        except Exception:
            pass
        raise


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if not LOGIN_PASSWORD:
        error = "LOGIN_PASSWORD is missing from Vercel Environment Variables."
    elif len(SESSION_SECRET) < 32:
        error = "SESSION_SECRET must be at least 32 characters long."

    if request.method == "POST" and error is None:
        if request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session.permanent = True
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
            "Configuration error: set LOGIN_PASSWORD and a SESSION_SECRET "
            "of at least 32 characters in Vercel.",
            500,
        )
    if not logged_in():
        return redirect(url_for("login"))
    return render_template("index.html")


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    if data.get("consentConfirmed") is not True:
        return jsonify({"error": "Confirm that recipients consented to receive email."}), 400

    sender_email = str(data.get("senderEmail", "")).strip()
    app_password = str(data.get("appPassword", "")).replace(" ", "")
    sender_name = str(data.get("senderName", "")).strip()[:100]
    subject = str(data.get("subject", "")).strip()
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True
    raw_recipients = data.get("recipients")

    if not EMAIL_RE.fullmatch(sender_email) or not sender_email.lower().endswith("@gmail.com"):
        return jsonify({"error": "Enter a valid @gmail.com sender address."}), 400
    if not app_password:
        return jsonify({"error": "Enter your Google App Password."}), 400
    if not isinstance(raw_recipients, list):
        return jsonify({"error": "Recipients must be a list."}), 400
    if any(not isinstance(item, str) or not EMAIL_RE.fullmatch(item.strip()) for item in raw_recipients):
        return jsonify({"error": "One or more recipient addresses are invalid."}), 400

    recipients = list(dict.fromkeys(item.strip() for item in raw_recipients))
    if not recipients:
        return jsonify({"error": "Add at least one recipient."}), 400
    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({"error": f"Maximum {MAX_RECIPIENTS} recipients per job."}), 400
    if not subject or not body:
        return jsonify({"error": "Subject and message body are required."}), 400
    if len(subject) > 200 or len(body) > 500000:
        return jsonify({"error": "Subject or message body is too long."}), 413

    # Stream one NDJSON event per recipient so the monitor updates live,
    # while reusing one authenticated SMTP connection for the entire job.
    def generate():
        sent = 0
        failed = 0
        processed = 0
        server = None

        def event(payload):
            return json_dumps(payload) + "\n"

        yield event({
            "type": "start",
            "total": len(recipients),
            "sent": 0,
            "failed": 0,
            "processed": 0,
            "remaining": len(recipients),
            "delayMs": MAIL_GAP_MS,
        })

        try:
            server = open_smtp(sender_email, app_password)

            for index, recipient in enumerate(recipients):
                try:
                    message = make_message(
                        recipient, subject, body, sender_name,
                        sender_email, html_mode
                    )
                    refused = server.send_message(message)

                    if refused:
                        failed += 1
                        status = "failed"
                        detail = "SMTP refused this recipient."
                    else:
                        sent += 1
                        status = "sent"
                        detail = "SMTP accepted the message; inbox placement is not guaranteed."

                except smtplib.SMTPAuthenticationError:
                    failed += 1
                    status = "failed"
                    detail = "Gmail authentication failed. Check the App Password."
                    processed += 1
                    yield event({
                        "type": "result", "email": recipient,
                        "status": status, "detail": detail,
                        "total": len(recipients), "sent": sent,
                        "failed": failed, "processed": processed,
                        "remaining": len(recipients) - processed,
                    })
                    break
                except (smtplib.SMTPException, OSError, TimeoutError) as exc:
                    failed += 1
                    status = "failed"
                    detail = f"SMTP error ({type(exc).__name__})."
                    logging.warning("SMTP error for recipient %s: %s", recipient, type(exc).__name__)
                    # Connection errors can leave delivery status uncertain;
                    # stop instead of retrying and risking duplicate sends.
                    processed += 1
                    yield event({
                        "type": "result", "email": recipient,
                        "status": status, "detail": detail,
                        "total": len(recipients), "sent": sent,
                        "failed": failed, "processed": processed,
                        "remaining": len(recipients) - processed,
                    })
                    break

                processed += 1
                yield event({
                    "type": "result", "email": recipient,
                    "status": status, "detail": detail,
                    "total": len(recipients), "sent": sent,
                    "failed": failed, "processed": processed,
                    "remaining": len(recipients) - processed,
                })

                if index < len(recipients) - 1 and MAIL_GAP_MS > 0:
                    time.sleep(MAIL_GAP_MS / 1000.0)

        except smtplib.SMTPAuthenticationError:
            logging.warning("Gmail SMTP authentication failed.")
            yield event({
                "type": "fatal",
                "error": "Gmail authentication failed. Check the Gmail address and App Password.",
            })
        except (smtplib.SMTPException, OSError, TimeoutError, ValueError) as exc:
            logging.warning("SMTP setup error: %s", type(exc).__name__)
            yield event({
                "type": "fatal",
                "error": f"Could not establish SMTP session ({type(exc).__name__}).",
            })
        except Exception:
            logging.exception("Unexpected error while streaming send job.")
            yield event({"type": "fatal", "error": "Unexpected server error. Check Vercel Runtime Logs."})
        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    pass

        yield event({
            "type": "done",
            "total": len(recipients),
            "sent": sent,
            "failed": failed,
            "processed": processed,
            "remaining": len(recipients) - processed,
            "delayMs": MAIL_GAP_MS,
        })

    return Response(
        stream_with_context(generate()),
        mimetype="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
        },
    )


def json_dumps(payload):
    import json
    return json.dumps(payload, ensure_ascii=False)


application = app

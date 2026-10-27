import os
import re
import ssl
import time
import smtplib
import html

from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, jsonify
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
handler = app

app.secret_key = os.environ.get("SESSION_SECRET", "")
app.config["MAX_CONTENT_LENGTH"] = 1_000_000
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("VERCEL") == "1"

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")

try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
except (ValueError, TypeError):
    SMTP_PORT = 465

try:
    MAIL_GAP_SECONDS = max(
        0.0,
        min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 10.0),
    )
except (ValueError, TypeError):
    MAIL_GAP_SECONDS = 1.0

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def logged_in():
    return session.get("logged_in") is True


def safe_header(value, limit=998):
    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()[:limit]
    )


def html_to_plain_text(source):
    source = str(source or "")
    source = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>", "", source
    )
    source = re.sub(r"(?i)<br\s*/?>", "\n", source)
    source = re.sub(
        r"(?i)</(p|div|li|tr|h[1-6])\s*>", "\n", source
    )
    source = re.sub(r"<[^>]+>", "", source)
    return html.unescape(source).strip()


def plain_body(body, html_mode):
    return html_to_plain_text(body) if html_mode else str(body or "").strip()


def choose_smart_replies(subject, body, html_mode):
    """Return three suggestions related to the email template."""
    text = (
        safe_header(subject, 200) + " " +
        plain_body(body, html_mode)
    ).lower()

    if any(word in text for word in (
        "quote", "quotation", "estimate", "pricing", "price", "cost"
    )):
        return [
            "Yes, please send the quote",
            "Please share the pricing details",
            "I'll review the quote",
        ]

    if any(word in text for word in (
        "seo", "ranking", "google", "backlink",
        "keyword", "traffic", "search engine"
    )):
        return [
            "Please share the SEO details",
            "I'm interested in your service",
            "What are the next steps?",
        ]

    if any(word in text for word in (
        "website", "web design", "web development"
    )):
        return [
            "Please share the website details",
            "I'd like to know more",
            "What would you recommend?",
        ]

    if any(word in text for word in (
        "meeting", "call", "appointment", "schedule"
    )):
        return [
            "Please share a suitable time",
            "That works for me",
            "Please send the meeting details",
        ]

    if any(word in text for word in (
        "document", "report", "attachment", "pdf"
    )):
        return [
            "Please send the document",
            "I'll review the details",
            "Please share the information",
        ]

    return [
        "Yes, please share the details",
        "I'm interested in learning more",
        "What are the next steps?",
    ]


def build_html_email(body, sender_name, sender_email, subject, html_mode):
    """
    Smart replies are deliberately excluded from the email body.
    Display them in the web-app UI instead.
    """
    if html_mode:
        return str(body or "")

    escaped_body = html.escape(str(body or "")).replace("\n", "<br>")

    return (
        '<div style="font-family:Arial,sans-serif;'
        'font-size:14px;font-weight:400;line-height:1.55;'
        'color:#303030;">'
        + escaped_body
        + '</div>'
    )


def send_one(
    to_email, subject, body, sender_name,
    sender_email, app_password, html_mode
):
    msg = EmailMessage()

    msg["From"] = formataddr((
        safe_header(sender_name, 100) or sender_email,
        sender_email,
    ))
    msg["To"] = to_email
    msg["Reply-To"] = sender_email
    msg["Subject"] = safe_header(subject, 200)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    msg.set_content(plain_body(body, html_mode))
    msg.add_alternative(
        build_html_email(
            body, sender_name, sender_email, subject, html_mode
        ),
        subtype="html",
    )

    context = ssl.create_default_context()

    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(
                SMTP_HOST, SMTP_PORT,
                timeout=25, context=context
            ) as server:
                server.ehlo()
                server.login(sender_email, app_password)
                refused = server.send_message(msg)

        elif SMTP_PORT == 587:
            with smtplib.SMTP(
                SMTP_HOST, SMTP_PORT, timeout=25
            ) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(sender_email, app_password)
                refused = server.send_message(msg)

        else:
            return False, "SMTP_PORT must be 465 or 587."

        if refused:
            return False, "Recipient rejected by SMTP server."

        return True, (
            "SMTP accepted the message; Inbox placement is not guaranteed."
        )

    except smtplib.SMTPAuthenticationError:
        return False, (
            "Gmail authentication failed. Check sender address "
            "and Google App Password."
        )
    except smtplib.SMTPRecipientsRefused:
        return False, "Recipient address rejected by SMTP server."
    except smtplib.SMTPException as exc:
        return False, f"SMTP error: {str(exc)[:160]}"
    except (OSError, TimeoutError) as exc:
        return False, f"Connection error: {str(exc)[:160]}"


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if not LOGIN_PASSWORD:
            error = "LOGIN_PASSWORD is not configured."
        elif request.form.get("password", "") == LOGIN_PASSWORD:
            session.clear()
            session["logged_in"] = True
            session.permanent = True
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


@app.post("/smart-replies")
def smart_replies():
    """Return suggestions for the app preview, not the email body."""
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    subject = safe_header(data.get("subject", ""), 200)
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    if not subject or not body:
        return jsonify({"replies": []})

    return jsonify({
        "replies": choose_smart_replies(subject, body, html_mode)
    })


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    recipients = data.get("recipients", [])
    sender_email = str(data.get("senderEmail", "")).strip().lower()
    app_password = re.sub(
        r"\s+", "", str(data.get("appPassword", ""))
    )
    sender_name = safe_header(data.get("senderName", ""), 100)
    subject = safe_header(data.get("subject", ""), 200)
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    if data.get("consentConfirmed") is not True:
        return jsonify({
            "error": "Confirm recipient permission first."
        }), 400

    if (
        not EMAIL_RE.fullmatch(sender_email)
        or not sender_email.endswith("@gmail.com")
    ):
        return jsonify({
            "error": "Enter a valid @gmail.com sender address."
        }), 400

    if not app_password:
        return jsonify({
            "error": "Enter your Google App Password."
        }), 400

    if not isinstance(recipients, list):
        return jsonify({
            "error": "Recipients must be a list."
        }), 400

    if len(recipients) > 25:
        return jsonify({
            "error": "Maximum 25 recipients per batch."
        }), 400

    if not subject or not body:
        return jsonify({
            "error": "Subject and message are required."
        }), 400

    cleaned = []
    seen = set()

    for item in recipients:
        if not isinstance(item, str):
            continue

        address = item.strip().lower()
        if EMAIL_RE.fullmatch(address) and address not in seen:
            cleaned.append(address)
            seen.add(address)

    if not cleaned:
        return jsonify({
            "error": "No valid recipient addresses found."
        }), 400

    results = []

    for index, recipient in enumerate(cleaned):
        ok, detail = send_one(
            recipient, subject, body, sender_name,
            sender_email, app_password, html_mode
        )

        results.append({
            "email": recipient,
            "status": "sent" if ok else "failed",
            "detail": detail,
        })

        if index < len(cleaned) - 1 and MAIL_GAP_SECONDS > 0:
            time.sleep(MAIL_GAP_SECONDS)

    sent = sum(item["status"] == "sent" for item in results)

    return jsonify({
        "total": len(results),
        "sent": sent,
        "failed": len(results) - sent,
        "results": results,
    })

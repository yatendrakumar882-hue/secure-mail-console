
import os
import re
import ssl
import time
import smtplib
import html
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from flask import Flask, render_template, request, redirect, url_for, session, jsonify

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
handler = app

app.secret_key = os.environ.get("SESSION_SECRET", "")
app.config.update(
    MAX_CONTENT_LENGTH=1_000_000,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")

try:
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
except (TypeError, ValueError):
    SMTP_PORT = 465

try:
    MAIL_GAP_SECONDS = max(
        0.0, min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 10.0)
    )
except (TypeError, ValueError):
    MAIL_GAP_SECONDS = 1.0

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def clean_header(value, limit=200):
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def logged_in():
    return session.get("logged_in") is True


def html_to_text(value):
    value = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", str(value or ""))
    value = re.sub(r"(?i)<br\s*/?>", "\n", value)
    value = re.sub(r"(?i)</(p|div|li|tr|h[1-6])\s*>", "\n", value)
    value = re.sub(r"<[^>]+>", "", value)
    return html.unescape(value).strip()


def suggest_replies(subject, body, html_mode=False):
    text = (
        clean_header(subject) + " " +
        (html_to_text(body) if html_mode else str(body or ""))
    ).lower()

    if any(x in text for x in ("quote", "quotation", "pricing", "price", "cost")):
        return [
            "Yes, please send the quote",
            "Please share the pricing details",
            "I'll review the quote",
        ]

    if any(x in text for x in ("meeting", "call", "appointment", "schedule")):
        return [
            "Please share a suitable time",
            "That works for me",
            "Please send the meeting details",
        ]

    if any(x in text for x in ("website", "web design", "web development")):
        return [
            "Please share more details",
            "I'd like to know more",
            "What are the next steps?",
        ]

    return [
        "Please share more information",
        "I'm interested in learning more",
        "What are the next steps?",
    ]


def send_one(recipient, subject, body, sender_name, sender_email,
             app_password, html_mode):
    msg = EmailMessage()
    msg["From"] = formataddr((
        clean_header(sender_name, 100) or sender_email,
        sender_email,
    ))
    msg["To"] = recipient
    # A normal recipient Reply goes to the authenticated Gmail sender.
    msg["Reply-To"] = sender_email
    msg["Subject"] = clean_header(subject)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    if html_mode:
        plain = html_to_text(body)
        safe_html = str(body or "")
    else:
        plain = str(body or "")
        safe_html = (
            '<div style="font-family:Arial,sans-serif;line-height:1.6;'
            'color:#202124;">'
            + html.escape(plain).replace("\n", "<br>")
            + "</div>"
        )

    # Keep the email body simple. Smart-reply suggestions are shown in the app,
    # not embedded as extra links in the delivered message.
    msg.set_content(plain)
    msg.add_alternative(safe_html, subtype="html")

    context = ssl.create_default_context()

    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(
                SMTP_HOST, SMTP_PORT, timeout=25, context=context
            ) as server:
                server.ehlo()
                server.login(sender_email, app_password)
                refused = server.send_message(msg)

        elif SMTP_PORT == 587:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=25) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(sender_email, app_password)
                refused = server.send_message(msg)

        else:
            return False, "SMTP_PORT must be 465 or 587."

        if refused:
            return False, "SMTP server refused the recipient."

        return True, (
            "Gmail SMTP accepted the message. This does not confirm "
            "delivery to the recipient's Primary Inbox."
        )

    except smtplib.SMTPAuthenticationError:
        return False, (
            "Gmail authentication failed. Check the Gmail address and "
            "Google App Password."
        )
    except smtplib.SMTPRecipientsRefused:
        return False, "Recipient rejected by the SMTP server."
    except smtplib.SMTPSenderRefused:
        return False, "Sender address rejected by the SMTP server."
    except smtplib.SMTPDataError as exc:
        return False, f"SMTP rejected the message content: {exc.smtp_code}."
    except smtplib.SMTPConnectError:
        return False, "Could not connect to the SMTP server."
    except smtplib.SMTPException as exc:
        return False, f"SMTP error: {str(exc)[:180]}"
    except (OSError, TimeoutError) as exc:
        return False, f"Network/timeout error: {str(exc)[:180]}"


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if len(app.secret_key) < 32:
            error = "Configure SESSION_SECRET with at least 32 random characters."
        elif not LOGIN_PASSWORD:
            error = "Configure LOGIN_PASSWORD in Vercel Environment Variables."
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
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    subject = clean_header(data.get("subject", ""))
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    if not subject or not body:
        return jsonify({"replies": []})

    return jsonify({"replies": suggest_replies(subject, body, html_mode)})


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    recipients = data.get("recipients", [])
    sender_email = str(data.get("senderEmail", "")).strip().lower()
    app_password = re.sub(r"\s+", "", str(data.get("appPassword", "")))
    sender_name = clean_header(data.get("senderName", ""), 100)
    subject = clean_header(data.get("subject", ""))
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    if len(app.secret_key) < 32:
        return jsonify({"error": "Configure SESSION_SECRET (32+ characters)."}), 500
    if data.get("consentConfirmed") is not True:
        return jsonify({"error": "Confirm that recipients agreed to receive the email."}), 400
    if not EMAIL_RE.fullmatch(sender_email) or not sender_email.endswith("@gmail.com"):
        return jsonify({"error": "Enter a valid @gmail.com sender address."}), 400
    if not app_password:
        return jsonify({"error": "Enter your Google App Password."}), 400
    if SMTP_PORT not in (465, 587):
        return jsonify({"error": "Set SMTP_PORT to 465 or 587."}), 500
    if not isinstance(recipients, list):
        return jsonify({"error": "Recipients must be a list."}), 400
    if len(recipients) > 25:
        return jsonify({"error": "Maximum 25 recipients per request."}), 400
    if not subject or not body:
        return jsonify({"error": "Subject and message are required."}), 400

    cleaned, seen = [], set()
    for item in recipients:
        if isinstance(item, str):
            address = item.strip().lower()
            if EMAIL_RE.fullmatch(address) and address not in seen:
                cleaned.append(address)
                seen.add(address)

    if not cleaned:
        return jsonify({"error": "No valid recipient addresses found."}), 400

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

        # Do not retry automatically on errors; retrying can duplicate messages.
        if index < len(cleaned) - 1 and MAIL_GAP_SECONDS > 0:
            time.sleep(MAIL_GAP_SECONDS)

    sent = sum(row["status"] == "sent" for row in results)
    return jsonify({
        "total": len(results),
        "sent": sent,
        "failed": len(results) - sent,
        "results": results,
    })


if __name__ == "__main__":
    app.run(debug=False)

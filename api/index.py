
import os
import re
import ssl
import time
import html
import smtplib
from urllib.parse import quote

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


def logged_in():
    return session.get("logged_in") is True


def clean_header(value, limit=200):
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def html_to_text(value):
    value = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", str(value or ""))
    value = re.sub(r"(?i)<br\s*/?>", "\n", value)
    value = re.sub(r"(?i)</(p|div|li|tr)\s*>", "\n", value)
    value = re.sub(r"<[^>]+>", "", value)
    return html.unescape(value).strip()


def get_reply_suggestions(subject, body, html_mode=False):
    text = (
        clean_header(subject) + " " +
        (html_to_text(body) if html_mode else str(body or ""))
    ).lower()

    if any(word in text for word in ("quote", "quotation", "pricing", "price", "cost")):
        return [
            "Yes, please send the quote",
            "Please share the pricing details",
            "I'll review the quote",
        ]

    if any(word in text for word in ("meeting", "call", "appointment", "schedule")):
        return [
            "Please share a suitable time",
            "That works for me",
            "Please send the meeting details",
        ]

    if any(word in text for word in ("website", "web design", "web development")):
        return [
            "Please share more details",
            "I'd like to know more",
            "What are the next steps?",
        ]

    return [
        "Yes, please share the details",
        "I'm interested in learning more",
        "What are the next steps?",
    ]


def build_email_html(body, sender_email, subject, html_mode):
    if html_mode:
        content_html = str(body or "")
    else:
        content_html = (
            '<div style="font-family:Arial,sans-serif;font-size:14px;'
            'line-height:1.6;color:#202124;">'
            + html.escape(str(body or "")).replace("\n", "<br>")
            + "</div>"
        )

    replies = get_reply_suggestions(subject, body, html_mode)
    mail_subject = quote("Re: " + clean_header(subject), safe="")
    buttons = []

    for reply in replies:
        mail_body = quote(reply, safe="")
        mailto = (
            f"mailto:{quote(sender_email, safe='@.+-_')}"
            f"?subject={mail_subject}&body={mail_body}"
        )
        buttons.append(
            '<a href="' + html.escape(mailto, quote=True) + '" '
            'style="display:inline-block;margin:0 6px 8px 0;padding:10px 13px;'
            'border:1px solid #dadce0;border-radius:7px;background:#ffffff;'
            'color:#0b57d0;text-decoration:none;font-family:Arial,sans-serif;'
            'font-size:14px;line-height:18px;">'
            + html.escape(reply)
            + "</a>"
        )

    return (
        '<div style="font-family:Arial,sans-serif;color:#202124;">'
        + content_html
        + '<div style="margin-top:18px;border-top:1px solid #dadce0;'
          'padding-top:15px;">'
        + "".join(buttons)
        + "</div></div>"
    )


def send_one(recipient, subject, body, sender_name, sender_email,
             app_password, html_mode):
    message = EmailMessage()
    message["From"] = formataddr((
        clean_header(sender_name, 100) or sender_email,
        sender_email,
    ))
    message["To"] = recipient
    message["Reply-To"] = sender_email
    message["Subject"] = clean_header(subject)
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()

    plain_body = html_to_text(body) if html_mode else str(body or "")
    replies = get_reply_suggestions(subject, body, html_mode)
    plain_body += "\n\nQuick reply options:\n" + "\n".join(
        f"- {reply}" for reply in replies
    )
    message.set_content(plain_body)

    message.add_alternative(
        build_email_html(body, sender_email, subject, html_mode),
        subtype="html",
    )

    context = ssl.create_default_context()

    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(
                SMTP_HOST, SMTP_PORT, timeout=25, context=context
            ) as server:
                server.ehlo()
                server.login(sender_email, app_password)
                refused = server.send_message(message)

        elif SMTP_PORT == 587:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=25) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(sender_email, app_password)
                refused = server.send_message(message)
        else:
            return False, "Set SMTP_PORT to 465 or 587."

        if refused:
            return False, "Recipient rejected by the SMTP server."

        return True, "SMTP accepted the message; Inbox placement is not guaranteed."

    except smtplib.SMTPAuthenticationError:
        return False, "Gmail login failed. Check the Gmail address and App Password."
    except smtplib.SMTPRecipientsRefused:
        return False, "Recipient address rejected by SMTP."
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
        if not app.secret_key or len(app.secret_key) < 32:
            error = "Set SESSION_SECRET to a random value of at least 32 characters."
        elif not LOGIN_PASSWORD:
            error = "Set LOGIN_PASSWORD in Vercel Environment Variables."
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
        return jsonify({"error": "Please log in again."}), 401

    data = request.get_json(silent=True) or {}
    subject = clean_header(data.get("subject", ""))
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    if not subject or not body:
        return jsonify({"replies": []})

    return jsonify({
        "replies": get_reply_suggestions(subject, body, html_mode)
    })


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please log in again."}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid request data."}), 400

    recipients = data.get("recipients", [])
    sender_email = str(data.get("senderEmail", "")).strip().lower()
    app_password = re.sub(r"\s+", "", str(data.get("appPassword", "")))
    sender_name = clean_header(data.get("senderName", ""), 100)
    subject = clean_header(data.get("subject", ""))
    body = str(data.get("body", "")).strip()
    html_mode = data.get("htmlMode") is True

    if not app.secret_key or len(app.secret_key) < 32:
        return jsonify({"error": "Configure SESSION_SECRET (32+ characters)."}), 500
    if data.get("consentConfirmed") is not True:
        return jsonify({"error": "Confirm recipient permission first."}), 400
    if not EMAIL_RE.fullmatch(sender_email) or not sender_email.endswith("@gmail.com"):
        return jsonify({"error": "Enter a valid @gmail.com sender address."}), 400
    if not app_password:
        return jsonify({"error": "Enter your Google App Password."}), 400
    if not isinstance(recipients, list):
        return jsonify({"error": "Recipients must be a list."}), 400
    if len(recipients) > 25:
        return jsonify({"error": "Maximum 25 recipients per request."}), 400
    if not subject or not body:
        return jsonify({"error": "Subject and message are required."}), 400

    cleaned = []
    seen = set()
    for item in recipients:
        if isinstance(item, str):
            address = item.strip().lower()
            if EMAIL_RE.fullmatch(address) and address not in seen:
                cleaned.append(address)
                seen.add(address)

    if not cleaned:
        return jsonify({"error": "No valid recipient addresses found."}), 400

    results = []
    for i, recipient in enumerate(cleaned):
        ok, detail = send_one(
            recipient, subject, body, sender_name, sender_email,
            app_password, html_mode
        )
        results.append({
            "email": recipient,
            "status": "sent" if ok else "failed",
            "detail": detail,
        })

        if i < len(cleaned) - 1 and MAIL_GAP_SECONDS > 0:
            time.sleep(MAIL_GAP_SECONDS)

    sent = sum(item["status"] == "sent" for item in results)
    return jsonify({
        "total": len(results),
        "sent": sent,
        "failed": len(results) - sent,
        "results": results,
    })

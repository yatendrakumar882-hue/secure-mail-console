import os
import re
import ssl
import time
import smtplib
import html
from urllib.parse import quote
from email.message import EmailMessage
from email.utils import formataddr
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)
handler = app
app.secret_key = os.environ.get(
    "SESSION_SECRET", "change-this-secret-in-vercel"
)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))

try:
    MAIL_GAP_SECONDS = max(
        0.0, min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 10.0)
    )
except (ValueError, TypeError):
    MAIL_GAP_SECONDS = 1.0

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SMART_REPLIES = ["Yes please do", "I am interested", "Sure please send"]


def logged_in():
    return session.get("logged_in") is True


def safe_header(value, limit=998):
    return str(value or "").replace("\r", " ").replace(
        "\n", " "
    ).strip()[:limit]


def html_to_plain_text(source):
    source = str(source or "")
    source = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", source)
    source = re.sub(r"(?i)<br\s*/?>", "\n", source)
    source = re.sub(r"(?i)</(p|div|li|tr)\s*>", "\n", source)
    source = re.sub(r"<[^>]+>", "", source)
    return html.unescape(source).strip()


def make_reply_mailto(sender_email, subject, reply_text, original_body, html_mode):
    reply_subject = (
        subject if subject.lower().startswith("re:") else f"Re: {subject}"
    )
    original_text = (
        html_to_plain_text(original_body) if html_mode
        else str(original_body or "")
    ).strip()
    quoted = "\n\n---------- Original message ----------\n" + original_text
    draft_body = reply_text + quoted

    return (
        f"mailto:{quote(sender_email, safe='@')}"
        f"?subject={quote(reply_subject, safe='')}"
        f"&body={quote(draft_body, safe='')}"
    )


def add_smart_reply_buttons(body, sender_email, subject, html_mode):
    if html_mode:
        message_body = str(body or "")
    else:
        message_body = (
            '<div style="white-space:pre-wrap;'
            'font-family:Arial,sans-serif;font-size:14px;'
            'line-height:1.55;color:#222;">'
            + html.escape(str(body or "")).replace("\n", "<br>")
            + "</div>"
        )

    buttons = []
    for reply_text in SMART_REPLIES:
        link = html.escape(
            make_reply_mailto(
                sender_email, subject, reply_text, body, html_mode
            ),
            quote=True
        )
        buttons.append(
            '<a href="' + link + '" '
            'style="display:inline-block;margin:5px 6px 5px 0;'
            'padding:9px 13px;border:1px solid #d8deea;'
            'border-radius:7px;background:#fafbfe;color:#315b9b;'
            'text-decoration:none;font:400 14px Arial,sans-serif;">'
            + html.escape(reply_text)
            + '</a>'
        )

    # Only the three reply buttons: no extra heading or explanation.
    return (
        '<div style="font-family:Arial,sans-serif;">'
        + message_body
        + '<div style="margin-top:20px;padding-top:12px;'
          'border-top:1px solid #e9ebef;">'
        + "".join(buttons)
        + '</div></div>'
    )


def send_smtp(
    to_email, subject, body, sender_name,
    sender_email, app_password, html_mode=False
):
    subject = safe_header(subject, 200)
    sender_name = safe_header(sender_name, 100) or sender_email

    message = EmailMessage()
    message["From"] = formataddr((sender_name, sender_email))
    message["To"] = to_email
    message["Reply-To"] = sender_email
    message["Subject"] = subject

    plain_body = (
        html_to_plain_text(body) if html_mode else str(body or "")
    )
    plain_body += "\n\nReply options:\n"

    for reply_text in SMART_REPLIES:
        draft = make_reply_mailto(
            sender_email, subject, reply_text, body, html_mode
        )
        plain_body += f"{reply_text}: {draft}\n"

    message.set_content(plain_body)
    message.add_alternative(
        add_smart_reply_buttons(
            body, sender_email, subject, html_mode
        ),
        subtype="html"
    )

    context = ssl.create_default_context()

    for attempt in range(2):
        try:
            if SMTP_PORT == 465:
                with smtplib.SMTP_SSL(
                    SMTP_HOST, SMTP_PORT, timeout=20, context=context
                ) as server:
                    server.ehlo()
                    server.login(sender_email, app_password)
                    refused = server.send_message(message)
            else:
                with smtplib.SMTP(
                    SMTP_HOST, SMTP_PORT, timeout=20
                ) as server:
                    server.ehlo()
                    server.starttls(context=context)
                    server.ehlo()
                    server.login(sender_email, app_password)
                    refused = server.send_message(message)

            if refused:
                return False, "Recipient rejected by SMTP server"

            return True, (
                "SMTP accepted the message; inbox placement "
                "is not guaranteed."
            )

        except smtplib.SMTPAuthenticationError:
            return False, (
                "Gmail login failed. Check the Gmail address "
                "and Google App Password."
            )
        except smtplib.SMTPRecipientsRefused:
            return False, "Recipient address rejected by SMTP server"
        except smtplib.SMTPDataError as exc:
            return False, f"SMTP rejected message (code {exc.smtp_code})"
        except (smtplib.SMTPException, OSError, TimeoutError) as exc:
            if attempt == 0:
                time.sleep(1)
            else:
                return False, f"SMTP connection failed: {str(exc)[:160]}"

    return False, "SMTP failed"


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        if not LOGIN_PASSWORD:
            error = "Set LOGIN_PASSWORD in Vercel Environment Variables first."
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
        return jsonify({"error": "Recipients must be a list."}), 400

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
        ok, detail = send_smtp(
            recipient, subject, body, sender_name,
            sender_email, app_password, html_mode
        )
        results.append({
            "email": recipient,
            "status": "sent" if ok else "failed",
            "detail": detail
        })

        if index < len(cleaned) - 1 and MAIL_GAP_SECONDS:
            time.sleep(MAIL_GAP_SECONDS)

    sent = sum(item["status"] == "sent" for item in results)
    return jsonify({
        "total": len(results),
        "sent": sent,
        "failed": len(results) - sent,
        "results": results
    })

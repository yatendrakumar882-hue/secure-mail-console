import os
import re
import ssl
import time
import smtplib
import html
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr, formatdate
from urllib.parse import quote

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
except (TypeError, ValueError):
    SMTP_PORT = 465

try:
    MAIL_GAP_SECONDS = max(
        0.0,
        min(float(os.environ.get("MAIL_GAP_SECONDS", "1")), 10.0)
    )
except (TypeError, ValueError):
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
    if html_mode:
        return html_to_plain_text(body)
    return str(body or "").strip()


def choose_smart_replies(subject, body, html_mode):
    """Choose three replies based on the email subject and message."""
    text = (
        safe_header(subject, 200) + " " +
        plain_body(body, html_mode)
    ).lower()

    # Website errors and screenshots
    if any(word in text for word in (
        "screenshot", "screen-shot", "glitch", "error",
        "not showing on google", "not appearing on google",
        "first page", "website issue", "site issue"
    )):
        return [
            "Please send the screenshot",
            "I'll check the website issue",
            "Please share the error details",
        ]

    # Quotes, estimates and pricing
    if any(word in text for word in (
        "quote", "quotation", "estimate", "pricing",
        "price", "cost"
    )):
        return [
            "Please resend the quote",
            "Please share the pricing details",
            "I'll review the estimate",
        ]

    # SEO and website services
    if any(word in text for word in (
        "seo", "google", "ranking", "website",
        "search result", "backlink", "keyword",
        "traffic", "audit", "optimization"
    )):
        return [
            "Please share the SEO details",
            "I'm interested—what are the next steps?",
            "Please explain the website issue",
        ]

    # Meetings and appointments
    if any(word in text for word in (
        "meeting", "call", "schedule",
        "appointment", "availability"
    )):
        return [
            "Please share a suitable time",
            "Yes, that time works for me",
            "Please send the meeting details",
        ]

    # Documents and reports
    if any(word in text for word in (
        "document", "file", "attachment",
        "report", "pdf"
    )):
        return [
            "Please send the document",
            "I'll review the report",
            "Please share the file details",
        ]

    return [
        "Please share more details",
        "I'll review this and get back to you",
        "What are the next steps?",
    ]


def make_reply_link(sender_email, subject, reply_text, quoted_text):
    reply_subject = (
        subject if subject.lower().startswith("re:")
        else f"Re: {subject}"
    )

    draft_body = f"{reply_text}\n\n{quoted_text}"

    return (
        f"mailto:{quote(sender_email, safe='@')}"
        f"?subject={quote(reply_subject, safe='')}"
        f"&body={quote(draft_body, safe='')}"
    )


def quoted_original(sender_name, sender_email, body, html_mode):
    name = safe_header(sender_name, 100) or sender_email
    original_text = plain_body(body, html_mode)

    now = datetime.now().astimezone()
    hour = now.strftime("%I").lstrip("0") or "12"
    date_text = (
        now.strftime("%a, %b %d, %Y at ")
        + hour + now.strftime(":%M %p")
    )

    quoted_lines = "\n".join(
        "> " + line for line in original_text.splitlines()
    )

    return (
        f"On {date_text} {name} <{sender_email}> wrote:\n"
        f"{quoted_lines}"
    )


def build_html_email(body, sender_name, sender_email,
                     subject, html_mode):
    if html_mode:
        content = str(body or "")
    else:
        content = (
            '<div style="white-space:pre-wrap;'
            'font-family:Arial,sans-serif;'
            'font-size:14px;font-weight:400;'
            'line-height:1.55;color:#303030;">'
            + html.escape(str(body or "")).replace("\n", "<br>")
            + "</div>"
        )

    replies = choose_smart_replies(subject, body, html_mode)
    quoted_text = quoted_original(
        sender_name, sender_email, body, html_mode
    )

    buttons = []

    for reply in replies:
        href = html.escape(
            make_reply_link(
                sender_email, subject, reply, quoted_text
            ),
            quote=True
        )

        buttons.append(
            '<a href="' + href + '" '
            'style="display:inline-block;vertical-align:middle;'
            'margin:7px 7px 0 0;padding:7px 12px;'
            'border:1px solid #dadce0;border-radius:6px;'
            'background:#fff;color:#1a73e8;'
            'font-family:Arial,sans-serif;font-size:14px;'
            'font-weight:400;line-height:1.35;'
            'text-decoration:none;">'
            + html.escape(reply) + '</a>'
        )

    # No extra "Quick reply" heading or instruction.
    return (
        '<div style="font-family:Arial,sans-serif;'
        'font-weight:400;">'
        + content
        + '<div style="margin-top:15px;padding-top:8px;'
          'border-top:1px solid #eceff1;">'
        + "".join(buttons)
        + '</div></div>'
    )


def send_one(to_email, subject, body, sender_name,
             sender_email, app_password, html_mode):
    msg = EmailMessage()

    msg["From"] = formataddr((
        safe_header(sender_name, 100) or sender_email,
        sender_email
    ))
    msg["To"] = to_email
    msg["Reply-To"] = sender_email
    msg["Subject"] = safe_header(subject, 200)
    msg["Date"] = formatdate(localtime=True)

    msg.set_content(plain_body(body, html_mode))

    msg.add_alternative(
        build_html_email(
            body, sender_name, sender_email,
            subject, html_mode
        ),
        subtype="html"
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
        else:
            with smtplib.SMTP(
                SMTP_HOST, SMTP_PORT, timeout=25
            ) as server:
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
                server.login(sender_email, app_password)
                refused = server.send_message(msg)

        if refused:
            return False, "Recipient rejected by SMTP server"

        return True, (
            "SMTP accepted the message; inbox placement "
            "is not guaranteed."
        )

    except smtplib.SMTPAuthenticationError:
        return False, (
            "Gmail authentication failed. Check your Gmail "
            "address and App Password."
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


@app.post("/send-batch")
def send_batch():
    if not logged_in():
        return jsonify({"error": "Please sign in again."}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    recipients = data.get("recipients", [])
    sender_email = str(
        data.get("senderEmail", "")
    ).strip().lower()
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

    sent = sum(
        item["status"] == "sent" for item in results
    )

    return jsonify({
        "total": len(results),
        "sent": sent,
        "failed": len(results) - sent,
        "results": results,
    })

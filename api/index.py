
import os
import re
import ssl
import json
import hmac
import html
import time
import smtplib
from pathlib import Path
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from email.utils import formataddr, make_msgid, formatdate

from flask import (
    Flask, request, render_template, redirect,
    url_for, jsonify, session, Response
)

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

if len(SESSION_SECRET) < 32:
    raise RuntimeError(
        "Set SESSION_SECRET to a random value of at least 32 characters."
    )
if not LOGIN_PASSWORD:
    raise RuntimeError("Set LOGIN_PASSWORD in Vercel.")

app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_SECURE=os.environ.get("VERCEL") == "1",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),
    MAX_CONTENT_LENGTH=1_000_000,
)

# Keep your original sending settings unchanged.
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 20
MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 6
SEND_DELAY_SECONDS = 0

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def clean(value, limit=250):
    return (
        str(value or "")
        .replace("\r", " ")
        .replace("\n", " ")
        .strip()[:limit]
    )


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
    value = str(value or "")
    value = re.sub(
        r"(?is)<\s*(script|style).*?>.*?</\s*\1\s*>", "", value
    )
    value = re.sub(r"(?i)<\s*br\s*/?\s*>", "\n", value)
    value = re.sub(
        r"(?i)</\s*(p|div|li|h[1-6])\s*>", "\n", value
    )
    value = re.sub(r"<[^>]*>", " ", value)
    value = html.unescape(value)
    value = re.sub(r"\n{3,}", "\n\n", value)
    return value.strip()


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
        result = result.replace(
            "{{" + key + "}}", recipient.get(key, "")
        )
    return result


def reply_suggestions(subject, body):
    text = (str(subject or "") + " " + html_to_text(body)).lower()

    if any(word in text for word in (
        "quote", "quotation", "pricing", "price", "cost"
    )):
        return [
            "Yes, please send the quote",
            "Please share the pricing details",
            "I'll review the quote",
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
        "website", "web design", "web development"
    )):
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


def build_reply_buttons(gmail, sender_name, subject, sent_time, body):
    buttons = []
    sender_display = clean(sender_name, 100) or gmail
    original_text = html_to_text(body)

    # Keep the quoted context compact: one header line, then the template.
    quoted_header = (
        f"On {sent_time} {sender_display} <{gmail}> wrote:"
    )

    for suggestion in reply_suggestions(subject, body):
        draft = (
            f"{suggestion}\n\n"
            f"{quoted_header}\n"
            f"{original_text}"
        )

        mailto = (
            "mailto:" + quote(gmail, safe="@.+-_")
            + "?subject=" + quote("Re: " + clean(subject, 200), safe="")
            + "&body=" + quote(draft, safe="")
        )

        buttons.append(
            '<a href="' + html.escape(mailto, quote=True) + '" '
            'style="display:inline-block;margin:0 6px 8px 0;'
            'padding:9px 13px;border:1px solid #dadce0;'
            'border-radius:7px;background:#ffffff;color:#0b57d0;'
            'text-decoration:none;font-family:Arial,sans-serif;'
            'font-size:14px;line-height:18px;">'
            + html.escape(suggestion)
            + "</a>"
        )

    return (
        '<div style="margin-top:18px;padding-top:14px;'
        'border-top:1px solid #dadce0;">'
        + "".join(buttons)
        + "</div>"
    )


def build_html_message(body, is_html, gmail, sender_name,
                       subject, sent_time):
    if is_html:
        message_html = str(body or "")
    else:
        message_html = (
            '<div style="font-family:Arial,sans-serif;'
            'font-size:14px;line-height:1.6;color:#202124;">'
            + html.escape(str(body or "")).replace("\n", "<br>")
            + "</div>"
        )

    buttons_html = build_reply_buttons(
        gmail=gmail,
        sender_name=sender_name,
        subject=subject,
        sent_time=sent_time,
        body=body,
    )

    return (
        '<div style="font-family:Arial,sans-serif;color:#202124;">'
        + message_html
        + buttons_html
        + "</div>"
    )


def send_one(gmail, app_password, sender_name, subject,
             body, is_html, recipient):
    # Preserve the original configured delay (currently zero).
    if SEND_DELAY_SECONDS:
        time.sleep(SEND_DELAY_SECONDS)

    personalized_subject = clean(personalize(subject, recipient), 250)
    personalized_body = personalize(body, recipient)

    sent_dt = datetime.now(ZoneInfo("Asia/Kolkata"))
    sent_time = sent_dt.strftime("%a, %b %d, %Y at %I:%M %p IST")

    msg = EmailMessage()
    msg["Subject"] = personalized_subject
    msg["From"] = formataddr((clean(sender_name, 100), gmail))
    msg["To"] = recipient["email"]
    msg["Reply-To"] = gmail
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    plain_text = (
        html_to_text(personalized_body)
        if is_html else personalized_body
    )
    msg.set_content(plain_text or "Please view this message in an HTML-capable email client.")

    msg.add_alternative(
        build_html_message(
            body=personalized_body,
            is_html=is_html,
            gmail=gmail,
            sender_name=sender_name,
            subject=personalized_subject,
            sent_time=sent_time,
        ),
        subtype="html",
    )

    context = ssl.create_default_context()

    with smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        context=context,
        timeout=SMTP_TIMEOUT,
    ) as smtp:
        smtp.ehlo()
        smtp.login(gmail, re.sub(r"\s+", "", app_password))
        refused = smtp.send_message(
            msg,
            from_addr=gmail,
            to_addrs=[recipient["email"]],
        )
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)

    return sent_time


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("login.html", error=None)

    entered_password = str(request.form.get("password", ""))
    if not hmac.compare_digest(entered_password, LOGIN_PASSWORD):
        return render_template(
            "login.html", error="Incorrect password."
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
        "smtp": "Gmail SMTP",
        "max_recipients": MAX_RECIPIENTS,
        "max_parallel_sends": MAX_PARALLEL_SENDS,
        "send_delay_seconds": SEND_DELAY_SECONDS,
    })


@app.route("/favicon.ico")
def favicon():
    return Response("", status=204)


@app.route("/sw.js")
def sw():
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

    sender_name = clean(data.get("sender_name", ""), 100)
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
        return error(
            f"Maximum {MAX_RECIPIENTS} unique recipients per batch."
        )

    def generate():
        total = len(recipients)
        sent = failed = 0

        yield event_line({
            "type": "start",
            "total": total,
            "sent": 0,
            "failed": 0,
            "remaining": total,
            "invalid_skipped": invalid,
        })

        with ThreadPoolExecutor(
            max_workers=min(MAX_PARALLEL_SENDS, total)
        ) as pool:
            jobs = {
                pool.submit(
                    send_one, gmail, password, sender_name,
                    subject, body, is_html, recipient
                ): recipient
                for recipient in recipients
            }

            for future in as_completed(jobs):
                recipient = jobs[future]
                item = {
                    "type": "progress",
                    "recipient": recipient["email"],
                }

                try:
                    sent_time = future.result()
                    sent += 1
                    item.update({
                        "result": "sent",
                        "sent_time": sent_time,
                    })

                except smtplib.SMTPAuthenticationError:
                    failed += 1
                    item.update({
                        "result": "failed",
                        "error": "Gmail authentication failed. Check address and App Password.",
                    })

                except smtplib.SMTPRecipientsRefused:
                    failed += 1
                    item.update({
                        "result": "failed",
                        "error": "Gmail refused this recipient.",
                    })

                except smtplib.SMTPResponseException as exc:
                    failed += 1
                    item.update({
                        "result": "failed",
                        "error": (
                            f"SMTP error {exc.smtp_code}: "
                            f"{str(exc.smtp_error)[:200]}"
                        ),
                    })

                except (smtplib.SMTPException, TimeoutError, OSError) as exc:
                    failed += 1
                    item.update({
                        "result": "failed",
                        "error": f"SMTP/network error: {str(exc)[:200]}",
                    })

                except Exception:
                    failed += 1
                    item.update({
                        "result": "failed",
                        "error": "Unexpected error. Check Vercel logs.",
                    })

                item.update({
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": total - sent - failed,
                })
                yield event_line(item)

        yield event_line({
            "type": "complete",
            "success": failed == 0,
            "message": (
                "Sending attempt finished. SMTP acceptance does not "
                "prove Inbox delivery."
            ),
            "total": total,
            "sent": sent,
            "failed": failed,
            "remaining": 0,
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

import os
import re
import ssl
import time
import secrets
import smtplib
import html
import random
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

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
    raise RuntimeError("Set SESSION_SECRET to at least 32 characters in Vercel.")
if not LOGIN_PASSWORD:
    raise RuntimeError("Set LOGIN_PASSWORD in Vercel.")

app.secret_key = SESSION_SECRET
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=1_000_000,
)

MAX_RECIPIENTS = 25
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

try:
    MAIL_GAP_MS = max(
        250,
        min(60000, int(os.environ.get("MAIL_GAP_MS", "1800")))
    )
except (ValueError, TypeError):
    MAIL_GAP_MS = 1800

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def clean_header(value, limit=998):
    return str(value or "").replace("\r", " ").replace(
        "\n", " "
    ).strip()[:limit]


def valid_email(value):
    value = str(value or "").strip()
    return len(value) <= 254 and bool(EMAIL_RE.fullmatch(value))


def authenticated():
    return session.get("authenticated") is True


def html_to_plain_text(source):
    source = str(source or "")
    source = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>", "", source
    )
    source = re.sub(r"(?i)<br\s*/?>", "\n", source)
    source = re.sub(r"(?i)</p\s*>", "\n\n", source)
    source = re.sub(r"(?i)</div\s*>", "\n", source)
    source = re.sub(r"<[^>]+>", "", source)
    return html.unescape(source).strip()


def expand_spintax(text):
    pattern = re.compile(r"\{([^{}|]+\|[^{}]+)\}")
    return pattern.sub(
        lambda match: random.choice(match.group(1).split("|")),
        str(text or ""),
    )


def normalize_recipient(item):
    if isinstance(item, str):
        return {"email": item.strip()}
    if isinstance(item, dict):
        return {
            str(key): str(value or "").strip()
            for key, value in item.items()
        }
    return {"email": ""}


def personalize(text, recipient):
    values = {
        "{{hi}}": recipient.get("hi", ""),
        "{{hello}}": recipient.get("hello", ""),
        "{{thanks}}": recipient.get("thanks", ""),
        "{{name}}": recipient.get("name", ""),
        "{{email}}": recipient.get("email", ""),
        "{{ref_code}}": recipient.get("ref_code", ""),
    }
    for token, value in values.items():
        text = text.replace(token, value)
    return expand_spintax(text)


def build_message(
    gmail, sender_name, subject, body, is_html, recipient
):
    gmail = gmail.strip().lower()
    sender_name = clean_header(sender_name, 100)
    subject = clean_header(subject, 200)
    body = str(body or "").replace("\x00", "")

    if is_html:
        message = MIMEMultipart("alternative")
        message.attach(
            MIMEText(html_to_plain_text(body), "plain", "utf-8")
        )
        message.attach(MIMEText(body, "html", "utf-8"))
    else:
        message = MIMEText(body, "plain", "utf-8")

    message["Subject"] = subject
    message["From"] = (
        formataddr((sender_name, gmail)) if sender_name else gmail
    )
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    return message


@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template(
            "login.html", error=None, turnstile_site_key=""
        )

    password = str(request.form.get("password", ""))
    if not secrets.compare_digest(password, LOGIN_PASSWORD):
        return render_template(
            "login.html",
            error="Incorrect password.",
            turnstile_site_key="",
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
    if not authenticated():
        return redirect(url_for("login"))
    return render_template("index.html", turnstile_site_key="")


@app.route("/send-batch", methods=["POST"])
def send_batch():
    if not authenticated():
        return jsonify({
            "error": "Session expired. Please log in again."
        }), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400

    sender_email = clean_header(
        data.get("senderEmail", ""), 254
    ).lower()
    app_password = re.sub(
        r"\s+", "", str(data.get("appPassword", ""))
    )
    sender_name = clean_header(data.get("senderName", ""), 100)
    subject = clean_header(data.get("subject", ""), 200)
    body = str(data.get("body", ""))
    html_mode = data.get("htmlMode") is True
    consent = data.get("consentConfirmed") is True
    recipients = data.get("recipients", [])

    if not valid_email(sender_email) or not sender_email.endswith(
        "@gmail.com"
    ):
        return jsonify({
            "error": "Enter a valid @gmail.com sender address."
        }), 400

    if not app_password:
        return jsonify({
            "error": "Google App Password is required."
        }), 400

    if not subject or not body.strip():
        return jsonify({
            "error": "Subject and message body are required."
        }), 400

    if not consent:
        return jsonify({
            "error": "Confirm recipients agreed to receive these emails."
        }), 400

    if (
        not isinstance(recipients, list)
        or not recipients
        or len(recipients) > MAX_RECIPIENTS
    ):
        return jsonify({
            "error": f"Provide 1 to {MAX_RECIPIENTS} recipients."
        }), 400

    clean_recipients = []
    seen = set()

    for item in recipients:
        recipient = normalize_recipient(item)
        email_address = recipient.get("email", "").strip().lower()

        if not valid_email(email_address):
            continue
        if email_address in seen:
            continue

        recipient["email"] = email_address
        seen.add(email_address)
        clean_recipients.append(recipient)

    if not clean_recipients:
        return jsonify({
            "error": "No valid recipient addresses found."
        }), 400

    results = []

    try:
        context = ssl.create_default_context()

        with smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            context=context,
            timeout=SMTP_TIMEOUT,
        ) as server:
            server.ehlo()
            server.login(sender_email, app_password)

            for index, recipient in enumerate(clean_recipients):
                email_address = recipient["email"]

                try:
                    personalized_subject = personalize(
                        subject, recipient
                    )
                    personalized_body = personalize(
                        body, recipient
                    )

                    message = build_message(
                        sender_email,
                        sender_name,
                        personalized_subject,
                        personalized_body,
                        html_mode,
                        email_address,
                    )

                    refused = server.sendmail(
                        sender_email,
                        [email_address],
                        message.as_string(),
                    )

                    if refused:
                        results.append({
                            "email": email_address,
                            "status": "failed",
                            "detail": "SMTP refused this recipient.",
                        })
                    else:
                        results.append({
                            "email": email_address,
                            "status": "sent",
                            "detail": (
                                "Accepted by Gmail SMTP; inbox "
                                "placement is not guaranteed."
                            ),
                        })

                except (
                    smtplib.SMTPException,
                    TimeoutError,
                    OSError,
                ) as exc:
                    results.append({
                        "email": email_address,
                        "status": "failed",
                        "detail": str(exc)[:250],
                    })

                if index < len(clean_recipients) - 1:
                    time.sleep(MAIL_GAP_MS / 1000.0)

    except smtplib.SMTPAuthenticationError:
        return jsonify({
            "error": (
                "Gmail login failed. Check the Gmail address and "
                "App Password. Do not use your normal password."
            )
        }), 401

    except (smtplib.SMTPException, TimeoutError, OSError) as exc:
        return jsonify({
            "error": f"SMTP connection failed: {str(exc)[:250]}"
        }), 502

    sent_count = sum(
        result["status"] == "sent" for result in results
    )
    failed_count = sum(
        result["status"] == "failed" for result in results
    )

    return jsonify({
        "success": True,
        "results": results,
        "sent": sent_count,
        "failed": failed_count,
    })


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "mailer": "Gmail SMTP SSL",
        "max_recipients": MAX_RECIPIENTS,
        "mail_gap_ms": MAIL_GAP_MS,
    })

import os
import re
import ssl
import time
import secrets
import smtplib
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

BASE_DIR = Path(__file__).resolve().parent.parent
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"), static_folder=str(BASE_DIR / "static"), static_url_path="/static")
handler = app

SESSION_SECRET = os.environ.get("SESSION_SECRET", "").strip()
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()
if len(SESSION_SECRET) < 32:
    raise RuntimeError("Set SESSION_SECRET in Vercel to a random value at least 32 characters long.")
if not LOGIN_PASSWORD:
    raise RuntimeError("Set LOGIN_PASSWORD in Vercel.")
app.secret_key = SESSION_SECRET
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=3600, MAX_CONTENT_LENGTH=1_000_000)

MAX_RECIPIENTS = 25
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25
# Set MAIL_GAP_MS in Vercel, e.g. 1800 = 1.8 seconds between recipients.
try:
    MAIL_GAP_MS = max(250, min(60000, int(os.environ.get("MAIL_GAP_MS", "1800"))))
except ValueError:
    MAIL_GAP_MS = 1800
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def clean_header(value, limit=998):
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()[:limit]


def valid_email(value):
    value = str(value or "").strip()
    return len(value) <= 254 and bool(EMAIL_RE.fullmatch(value))


def authenticated():
    return session.get("authenticated") is True


def html_to_plain_text(html):
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", str(html or ""))
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</p\s*>", "\n\n", text)
    text = re.sub(r"(?i)</div\s*>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    for old, new in (("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'")):
        text = text.replace(old, new)
    return text.strip()


def expand_spintax(text):
    # Supports simple, non-nested forms such as {Hello|Hi|Hey}.
    pattern = re.compile(r"\{([^{}|]+\|[^{}]+)\}")
    import random
    return pattern.sub(lambda m: random.choice(m.group(1).split("|")), str(text or ""))


def normalize_recipient(item):
    if isinstance(item, str):
        return {"email": item.strip()}
    if isinstance(item, dict):
        return {str(k): str(v or "").strip() for k, v in item.items()}
    return {"email": ""}


def personalize(text, recipient):
    values = {"{{hi}}": recipient.get("hi", ""), "{{hello}}": recipient.get("hello", ""), "{{thanks}}": recipient.get("thanks", ""), "{{name}}": recipient.get("name", ""), "{{email}}": recipient.get("email", ""), "{{ref_code}}": recipient.get("ref_code", "")}
    for token, value in values.items():
        text = text.replace(token, value)
    return expand_spintax(text)


def build_message(gmail, sender_name, subject, body, is_html, recipient):
    gmail = gmail.strip().lower()
    sender_name = clean_header(sender_name, 200)
    subject = clean_header(subject, 200)
    body = str(body or "").replace("\x00", "")
    msg = MIMEMultipart("alternative") if is_html else MIMEText(body, "plain", "utf-8")
    if is_html:
        msg.attach(MIMEText(html_to_plain_text(body), "plain", "utf-8"))
        msg.attach(MIMEText(body, "html", "utf-8"))
    msg["Subject"] = subject
    msg["From"] = formataddr((sender_name, gmail)) if sender_name else gmail
    msg["To"] = recipient
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    return msg


@app.route("/login", methods=["GET", "POST"])
def login():
    if authenticated():
        return redirect(url_for("home"))
    if request.method == "GET":
        return render_template("login.html", error=None, turnstile_site_key="")
    password = str(request.form.get("password", ""))
    if not secrets.compare_digest(password, LOGIN_PASSWORD):
        return render_template("login.html", error="Incorrect password.", turnstile_site_key=""), 401
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
        return jsonify({"error": "Authentication required. Please log in again."}), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON request."}), 400
    sender_email = clean_header(data.get("senderEmail", ""), 254).lower()
    app_password = re.sub(r"\s+", "", str(data.get("appPassword", "")))
    sender_name = clean_header(data.get("senderName", ""), 100)
    subject = clean_header(data.get("subject", ""), 200)
    body = str(data.get("body", ""))
    html_mode = data.get("htmlMode") is True
    consent = data.get("consentConfirmed") is True
    recipients = data.get("recipients", [])
    if not valid_email(sender_email) or not sender_email.endswith("@gmail.com"):
        return jsonify({"error": "Enter a valid @gmail.com sender address."}), 400
    if not app_password:
        return jsonify({"error": "Google App Password is required."}), 400
    if not subject or not body.strip():
        return jsonify({"error": "Subject and message body are required."}), 400
    if not consent:
        return jsonify({"error": "Confirm that recipients agreed to receive this email."}), 400
    if not isinstance(recipients, list) or not recipients or len(recipients) > MAX_RECIPIENTS:
        return jsonify({"error": f"Provide 1 to {MAX_RECIPIENTS} recipients per request."}), 400
    clean = []
    seen = set()
    for item in recipients:
        r = normalize_recipient(item)
        email = r.get("email", "").strip().lower()
        if valid_email(email) and email not in seen:
            r["email"] = email
            seen.add(email)
            clean.append(r)
    if not clean:
        return jsonify({"error": "No valid recipient addresses found."}), 400
    results = []
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=SMTP_TIMEOUT) as server:
            server.ehlo()
            server.login(sender_email, app_password)
            for index, recipient in enumerate(clean):
                email = recipient["email"]
                try:
                    personalized_subject = personalize(subject, recipient)
                    personalized_body = personalize(body, recipient)
                    message = build_message(sender_email, sender_name, personalized_subject, personalized_body, html_mode, email)
                    refused = server.sendmail(sender_email, [email], message.as_string())
                    if refused:
                        results.append({"email": email, "status": "failed", "detail": "SMTP refused this recipient."})
                    else:
                        results.append({"email": email, "status": "sent", "detail": "Accepted by Gmail SMTP; inbox placement is not guaranteed."})
                except smtplib.SMTPRecipientsRefused:
                    results.append({"email": email, "status": "failed", "detail": "SMTP refused this recipient."})
                except (smtplib.SMTPException, TimeoutError, OSError) as exc:
                    results.append({"email": email, "status": "failed", "detail": str(exc)[:250]})
                if index < len(clean) - 1:
                    time.sleep(MAIL_GAP_MS / 1000.0)
    except smtplib.SMTPAuthenticationError:
        return jsonify({"error": "Gmail login failed. Check the Gmail address and App Password; use an App Password, not your normal password."}), 401
    except (smtplib.SMTPException, TimeoutError, OSError) as exc:
        return jsonify({"error": f"SMTP connection failed: {str(exc)[:250]}"}), 502
    return jsonify({"success": True, "results": results, "sent": sum(x["status"] == "sent" for x in results), "failed": sum(x["status"] == "failed" for x in results)})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "mailer": "Gmail SMTP SSL", "max_recipients": MAX_RECIPIENTS, "mail_gap_ms": MAIL_GAP_MS})

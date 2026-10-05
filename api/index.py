import os
import re
import json
import uuid
import secrets
import smtplib
import urllib.request
import urllib.parse

from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    session,
    Response,
    stream_with_context,
)


# =========================================================
# PATHS
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)


# =========================================================
# FLASK APP
# =========================================================

app = Flask(
    __name__,
    template_folder=BASE_DIR,
)

# Important for Vercel
handler = app


# =========================================================
# CONFIG
# =========================================================

app.secret_key = os.environ.get(
    "SESSION_SECRET",
    secrets.token_hex(32)
)

LOGIN_PASSWORD = os.environ.get(
    "LOGIN_PASSWORD",
    ""
).strip()

TURNSTILE_SECRET_KEY = os.environ.get(
    "TURNSTILE_SECRET_KEY",
    ""
).strip()

MAX_RECIPIENTS = 25

# Keep parallelism controlled.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 30


# =========================================================
# EMAIL VALIDATION
# =========================================================

EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def is_valid_email(email):
    if not email:
        return False

    email = email.strip()

    if len(email) > 254:
        return False

    return bool(
        EMAIL_REGEX.match(email)
    )


def clean_recipients(values):

    result = []
    seen = set()

    if not isinstance(values, list):
        return result

    for value in values:

        if not isinstance(value, str):
            continue

        parts = re.split(
            r"[\s,;]+",
            value
        )

        for part in parts:

            email = part.strip().lower()

            if not email:
                continue

            if not is_valid_email(email):
                continue

            if email in seen:
                continue

            seen.add(email)
            result.append(email)

            if len(result) >= MAX_RECIPIENTS:
                return result

    return result


# =========================================================
# SPINTAX
# =========================================================

def expand_spintax(text):

    if not isinstance(text, str):
        return ""

    pattern = re.compile(
        r"\{([^{}]+)\}"
    )

    def replace(match):

        choices = [
            item.strip()
            for item in match.group(1).split("|")
            if item.strip()
        ]

        if not choices:
            return match.group(0)

        return secrets.choice(
            choices
        )

    for _ in range(10):

        new_text = pattern.sub(
            replace,
            text
        )

        if new_text == text:
            break

        text = new_text

    return text


# =========================================================
# HTML -> TEXT FALLBACK
# =========================================================

def html_to_text(value):

    if not value:
        return ""

    value = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>",
        "",
        value
    )

    value = re.sub(
        r"(?i)<br\s*/?>",
        "\n",
        value
    )

    value = re.sub(
        r"(?i)</p\s*>",
        "\n\n",
        value
    )

    value = re.sub(
        r"<[^>]+>",
        "",
        value
    )

    return value.strip()


# =========================================================
# BUILD EMAIL
# =========================================================

def build_message(
    sender_name,
    gmail,
    recipient,
    subject,
    body,
    is_html
):

    final_subject = expand_spintax(
        subject
    )

    final_body = expand_spintax(
        body
    )

    message = EmailMessage()

    message["From"] = (
        f"{sender_name} <{gmail}>"
    )

    message["To"] = recipient

    message["Subject"] = (
        final_subject
    )

    message["Date"] = formatdate(
        localtime=True,
        usegmt=True
    )

    message["Message-ID"] = make_msgid()

    message["MIME-Version"] = "1.0"

    if is_html:

        text_version = html_to_text(
            final_body
        )

        if not text_version:
            text_version = final_body

        message.set_content(
            text_version,
            charset="utf-8"
        )

        message.add_alternative(
            final_body,
            subtype="html",
            charset="utf-8"
        )

    else:

        message.set_content(
            final_body,
            charset="utf-8"
        )

    return message


# =========================================================
# TURNSTILE
# =========================================================

def verify_turnstile(
    token,
    remote_ip=None
):

    # If Turnstile secret is not configured,
    # do not block the application.
    if not TURNSTILE_SECRET_KEY:
        return True

    if not token:
        return False

    data = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token
    }

    if remote_ip:
        data["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(
        data
    ).encode("utf-8")

    try:

        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=encoded,
            headers={
                "Content-Type":
                    "application/x-www-form-urlencoded",
                "User-Agent":
                    "Secure-Mail-Console/1.0"
            },
            method="POST"
        )

        with urllib.request.urlopen(
            req,
            timeout=15
        ) as response:

            raw = response.read().decode(
                "utf-8",
                errors="replace"
            )

        result = json.loads(raw)

        return bool(
            result.get("success")
        )

    except Exception:
        return False


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if session.get(
        "authenticated"
    ) is True:

        return redirect(
            url_for("index")
        )

    error = None

    if request.method == "POST":

        password = request.form.get(
            "password",
            ""
        )

        if (
            LOGIN_PASSWORD
            and secrets.compare_digest(
                password,
                LOGIN_PASSWORD
            )
        ):

            session.clear()

            session["authenticated"] = True

            return redirect(
                url_for("index")
            )

        error = "Invalid password."

    return render_template(
        "login.html",
        error=error
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# MAIN PAGE
# =========================================================

@app.route("/")
def index():

    if session.get(
        "authenticated"
    ) is not True:

        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get(
            "TURNSTILE_SITE_KEY",
            ""
        )
    )


# =========================================================
# SMTP WORKER
# =========================================================

def smtp_worker(
    gmail,
    app_password,
    jobs
):

    results = []

    server = None

    try:

        # One persistent connection per worker.
        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=SMTP_TIMEOUT
        )

        server.login(
            gmail,
            app_password
        )

        for job in jobs:

            recipient = job["recipient"]
            message = job["message"]

            try:

                refused = server.send_message(
                    message,
                    from_addr=gmail,
                    to_addrs=[recipient]
                )

                if refused:

                    results.append(
                        (
                            recipient,
                            False,
                            f"SMTP refused: {refused}"
                        )
                    )

                else:

                    results.append(
                        (
                            recipient,
                            True,
                            ""
                        )
                    )

            except smtplib.SMTPServerDisconnected as exc:

                results.append(
                    (
                        recipient,
                        False,
                        f"SMTP disconnected: {exc}"
                    )
                )

                # Do not blindly retry.
                # It could create duplicate delivery.
                break

            except smtplib.SMTPException as exc:

                results.append(
                    (
                        recipient,
                        False,
                        f"SMTP error: {exc}"
                    )
                )

            except Exception as exc:

                results.append(
                    (
                        recipient,
                        False,
                        f"Send error: {exc}"
                    )
                )

    except smtplib.SMTPAuthenticationError as exc:

        for job in jobs:

            results.append(
                (
                    job["recipient"],
                    False,
                    f"SMTP authentication failed: {exc}"
                )
            )

    except smtplib.SMTPException as exc:

        for job in jobs:

            results.append(
                (
                    job["recipient"],
                    False,
                    f"SMTP connection error: {exc}"
                )
            )

    except Exception as exc:

        for job in jobs:

            results.append(
                (
                    job["recipient"],
                    False,
                    f"Worker error: {exc}"
                )
            )

    finally:

        if server is not None:

            try:
                server.quit()

            except Exception:

                try:
                    server.close()
                except Exception:
                    pass


    # Mark jobs not processed because the
    # connection ended.
    processed = {
        item[0]
        for item in results
    }

    for job in jobs:

        recipient = job["recipient"]

        if recipient not in processed:

            results.append(
                (
                    recipient,
                    False,
                    "SMTP connection ended before sending."
                )
            )

    return results


# =========================================================
# SEND BATCH
# =========================================================

@app.route(
    "/send-batch",
    methods=["POST"]
)
def send_batch():

    if session.get(
        "authenticated"
    ) is not True:

        return jsonify(
            {
                "message":
                    "Authentication required."
            }
        ), 401


    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify(
            {
                "message":
                    "Invalid request."
            }
        ), 400


    sender_name = str(
        data.get(
            "sender_name",
            ""
        )
    ).strip()


    gmail = str(
        data.get(
            "gmail",
            ""
        )
    ).strip().lower()


    app_password = str(
        data.get(
            "app_password",
            ""
        )
    ).strip()


    subject = str(
        data.get(
            "subject",
            ""
        )
    ).strip()


    body = data.get(
        "body",
        ""
    )


    is_html = bool(
        data.get(
            "is_html",
            False
        )
    )


    recipients = clean_recipients(
        data.get(
            "recipients",
            []
        )
    )


    turnstile_token = str(
        data.get(
            "turnstile_token",
            ""
        )
    ).strip()


    # =====================================================
    # VALIDATION
    # =====================================================

    if not sender_name:

        return jsonify(
            {
                "message":
                    "Enter sender name."
            }
        ), 400


    if not is_valid_email(gmail):

        return jsonify(
            {
                "message":
                    "Enter a valid Gmail address."
            }
        ), 400


    if not app_password:

        return jsonify(
            {
                "message":
                    "Enter Google App Password."
            }
        ), 400


    if not subject:

        return jsonify(
            {
                "message":
                    "Enter email subject."
            }
        ), 400


    if (
        not isinstance(body, str)
        or not body.strip()
    ):

        return jsonify(
            {
                "message":
                    "Enter message body."
            }
        ), 400


    if not recipients:

        return jsonify(
            {
                "message":
                    "Add at least one valid recipient."
            }
        ), 400


    # =====================================================
    # TURNSTILE
    # =====================================================

    remote_ip = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
    )

    if remote_ip and "," in remote_ip:

        remote_ip = (
            remote_ip
            .split(",")[0]
            .strip()
        )


    if not verify_turnstile(
        turnstile_token,
        remote_ip
    ):

        return jsonify(
            {
                "message":
                    "Cloudflare verification failed."
            }
        ), 403


    # =====================================================
    # BUILD JOBS
    # =====================================================

    jobs = []

    for recipient in recipients:

        try:

            message = build_message(
                sender_name,
                gmail,
                recipient,
                subject,
                body,
                is_html
            )

            jobs.append(
                {
                    "recipient":
                        recipient,
                    "message":
                        message
                }
            )

        except Exception as exc:

            return jsonify(
                {
                    "message":
                        f"Could not build email: {exc}"
                }
            ), 400


    total = len(jobs)


    # =====================================================
    # GENERATOR
    # =====================================================

    def generate():

        sent = 0
        failed = 0


        yield (
            json.dumps(
                {
                    "type": "start",
                    "total": total,
                    "sent": 0,
                    "failed": 0,
                    "remaining": total
                },
                ensure_ascii=False
            )
            + "\n"
        )


        worker_count = min(
            MAX_PARALLEL_SENDS,
            total
        )


        worker_batches = [
            []
            for _ in range(
                worker_count
            )
        ]


        for index, job in enumerate(jobs):

            worker_batches[
                index % worker_count
            ].append(job)


        with ThreadPoolExecutor(
            max_workers=worker_count
        ) as executor:

            futures = [
                executor.submit(
                    smtp_worker,
                    gmail,
                    app_password,
                    batch
                )
                for batch in worker_batches
            ]


            for future in as_completed(
                futures
            ):

                try:

                    results = future.result()

                except Exception as exc:

                    results = []

                    failed += 1

                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "total":
                                    total,
                                "sent":
                                    sent,
                                "failed":
                                    failed,
                                "remaining":
                                    max(
                                        0,
                                        total
                                        - sent
                                        - failed
                                    ),
                                "message":
                                    str(exc)
                            },
                            ensure_ascii=False
                        )
                        + "\n"
                    )

                    continue


                for (
                    recipient,
                    success,
                    error_message
                ) in results:

                    if success:
                        sent += 1
                    else:
                        failed += 1


                    remaining = max(
                        0,
                        total
                        - sent
                        - failed
                    )


                    yield (
                        json.dumps(
                            {
                                "type":
                                    "progress",
                                "total":
                                    total,
                                "sent":
                                    sent,
                                "failed":
                                    failed,
                                "remaining":
                                    remaining,
                                "recipient":
                                    recipient,
                                "success":
                                    success,
                                "error":
                                    error_message
                                    if not success
                                    else ""
                            },
                            ensure_ascii=False
                        )
                        + "\n"
                    )


        # =================================================
        # FINAL EVENT
        # =================================================

        if failed == 0:

            final_message = (
                "Email sending completed successfully."
            )

        else:

            final_message = (
                f"Sending completed: "
                f"{sent} accepted, "
                f"{failed} failed."
            )


        yield (
            json.dumps(
                {
                    "type":
                        "complete",
                    "total":
                        total,
                    "sent":
                        sent,
                    "failed":
                        failed,
                    "remaining":
                        0,
                    "message":
                        final_message
                },
                ensure_ascii=False
            )
            + "\n"
        )


    # =====================================================
    # VERCEL-SAFE STREAM RESPONSE
    # =====================================================

    response = Response(
        stream_with_context(
            generate()
        ),
        mimetype="application/x-ndjson"
    )

    response.headers[
        "Cache-Control"
    ] = "no-cache, no-store, must-revalidate"

    response.headers[
        "Pragma"
    ] = "no-cache"

    response.headers[
        "X-Accel-Buffering"
    ] = "no"

    return response


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():

    return jsonify(
        {
            "status": "ok",
            "parallel_sends":
                MAX_PARALLEL_SENDS,
            "max_recipients":
                MAX_RECIPIENTS,
            "smtp":
                SMTP_HOST,
            "smtp_port":
                SMTP_PORT
        }
    )


# =========================================================
# LOCAL RUN
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                "5000"
            )
        ),
        debug=False
    )

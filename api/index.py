import os
import re
import json
import html
import uuid
import smtplib
import secrets
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
# APP
# =========================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=BASE_DIR,
    static_folder=os.path.join(BASE_DIR, "static"),
)

# Vercel / WSGI compatibility
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

# Keep this conservative.
# Two persistent SMTP connections = two emails can be
# processed at the same time without creating a new
# SMTP connection for every single recipient.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465

SMTP_TIMEOUT = 30


# =========================================================
# HELPERS
# =========================================================

EMAIL_REGEX = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


def is_valid_email(value):
    if not value:
        return False

    value = value.strip()

    if len(value) > 254:
        return False

    return bool(EMAIL_REGEX.match(value))


def clean_recipients(values):
    """
    Clean, validate and deduplicate recipients.

    Frontend already limits the list, but backend enforces
    the same limit so it cannot be bypassed accidentally.
    """

    cleaned = []
    seen = set()

    if not isinstance(values, list):
        return cleaned

    for item in values:
        if not isinstance(item, str):
            continue

        # Support accidental comma/semicolon/newline input
        parts = re.split(r"[\s,;]+", item)

        for part in parts:
            email = part.strip().lower()

            if not email:
                continue

            if not is_valid_email(email):
                continue

            if email in seen:
                continue

            seen.add(email)
            cleaned.append(email)

            if len(cleaned) >= MAX_RECIPIENTS:
                return cleaned

    return cleaned


def expand_spintax(text):
    """
    Simple spintax support:

    {Hello|Hi|Hey}
    """

    if not isinstance(text, str):
        return ""

    pattern = re.compile(r"\{([^{}]+)\}")

    def replace(match):
        choices = [
            item.strip()
            for item in match.group(1).split("|")
            if item.strip()
        ]

        if not choices:
            return match.group(0)

        # secrets.choice gives good random distribution.
        return secrets.choice(choices)

    # Repeat a few times to support nested/simple combinations.
    for _ in range(10):
        new_text = pattern.sub(replace, text)

        if new_text == text:
            break

        text = new_text

    return text


def strip_html_tags(value):
    """
    Creates a basic text fallback for HTML mail.
    """

    if not value:
        return ""

    value = re.sub(
        r"(?is)<(script|style).*?>.*?</\1>",
        "",
        value,
    )

    value = re.sub(
        r"(?i)<br\s*/?>",
        "\n",
        value,
    )

    value = re.sub(
        r"(?i)</p\s*>",
        "\n\n",
        value,
    )

    value = re.sub(
        r"<[^>]+>",
        "",
        value,
    )

    return html.unescape(value).strip()


def build_message(
    sender_name,
    gmail,
    recipient,
    subject,
    body,
    is_html,
):
    """
    Build one standards-compliant email.

    A fresh Message-ID is generated for every recipient.
    """

    final_subject = expand_spintax(subject)
    final_body = expand_spintax(body)

    message = EmailMessage()

    message["From"] = f"{sender_name} <{gmail}>"
    message["To"] = recipient
    message["Subject"] = final_subject

    # Standard mail headers
    message["Date"] = formatdate(
        localtime=True,
        usegmt=True,
    )

    message["Message-ID"] = make_msgid()

    # Explicit MIME version
    message["MIME-Version"] = "1.0"

    if is_html:
        # Text fallback + HTML version.
        fallback = strip_html_tags(final_body)

        if not fallback:
            fallback = final_body

        message.set_content(
            fallback,
            charset="utf-8",
        )

        message.add_alternative(
            final_body,
            subtype="html",
            charset="utf-8",
        )

    else:
        message.set_content(
            final_body,
            charset="utf-8",
        )

    return message


# =========================================================
# TURNSTILE
# =========================================================

def verify_turnstile(token, remote_ip=None):
    """
    Verify Cloudflare Turnstile before SMTP work starts.
    """

    # If Turnstile is not configured, allow local/simple
    # deployments to work.
    if not TURNSTILE_SECRET_KEY:
        return True

    if not token:
        return False

    data = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        data["remoteip"] = remote_ip

    encoded = urllib.parse.urlencode(data).encode("utf-8")

    try:
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=encoded,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Secure-Mail-Console/1.0",
            },
            method="POST",
        )

        with urllib.request.urlopen(
            req,
            timeout=15,
        ) as response:

            raw = response.read().decode(
                "utf-8",
                errors="replace",
            )

        result = json.loads(raw)

        return bool(
            result.get("success")
        )

    except Exception:
        return False


# =========================================================
# AUTH
# =========================================================

def is_logged_in():
    return session.get("authenticated") is True


@app.route("/login", methods=["GET", "POST"])
def login():

    if is_logged_in():
        return redirect(url_for("index"))

    error = None

    if request.method == "POST":

        password = request.form.get(
            "password",
            "",
        )

        if (
            LOGIN_PASSWORD
            and secrets.compare_digest(
                password,
                LOGIN_PASSWORD,
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
        error=error,
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    if not is_logged_in():
        return redirect(
            url_for("login")
        )

    return render_template(
        "index.html",
        turnstile_site_key=os.environ.get(
            "TURNSTILE_SITE_KEY",
            "",
        ),
    )


# =========================================================
# ONE SMTP WORKER
# =========================================================

def smtp_worker(
    gmail,
    app_password,
    worker_items,
):
    """
    One worker owns one SMTP connection.

    The same authenticated SMTP connection is reused for
    multiple recipients handled by this worker.

    Returns:
        [(recipient, True, ""), ...]
    """

    results = []

    server = None

    try:

        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=SMTP_TIMEOUT,
        )

        server.login(
            gmail,
            app_password,
        )

        for item in worker_items:

            recipient = item["recipient"]
            message = item["message"]

            try:

                refused = server.send_message(
                    message,
                    from_addr=gmail,
                    to_addrs=[recipient],
                )

                # send_message normally returns an empty dict
                # when the server accepted all recipients.
                if refused:
                    results.append(
                        (
                            recipient,
                            False,
                            f"SMTP refused recipient: {refused}",
                        )
                    )
                else:
                    results.append(
                        (
                            recipient,
                            True,
                            "",
                        )
                    )

            except smtplib.SMTPServerDisconnected as exc:

                # Connection was lost.
                #
                # We deliberately do NOT automatically resend the
                # same message here because the remote server may
                # have accepted it just before the connection died.
                #
                # Blind retry can create duplicate emails.
                results.append(
                    (
                        recipient,
                        False,
                        f"SMTP connection lost: {exc}",
                    )
                )

                # Stop this worker because its connection is dead.
                break

            except smtplib.SMTPException as exc:

                results.append(
                    (
                        recipient,
                        False,
                        f"SMTP error: {exc}",
                    )
                )

            except Exception as exc:

                results.append(
                    (
                        recipient,
                        False,
                        f"Send error: {exc}",
                    )
                )

    except smtplib.SMTPAuthenticationError as exc:

        # Login/authentication failure applies to this worker.
        for item in worker_items:
            results.append(
                (
                    item["recipient"],
                    False,
                    f"SMTP authentication failed: {exc}",
                )
            )

    except smtplib.SMTPException as exc:

        for item in worker_items:
            results.append(
                (
                    item["recipient"],
                    False,
                    f"SMTP connection error: {exc}",
                )
            )

    except Exception as exc:

        for item in worker_items:
            results.append(
                (
                    item["recipient"],
                    False,
                    f"SMTP worker error: {exc}",
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

    # If a connection died before all worker items were
    # processed, mark those remaining items as failed.
    already_reported = {
        recipient
        for recipient, _, _ in results
    }

    for item in worker_items:

        recipient = item["recipient"]

        if recipient not in already_reported:

            results.append(
                (
                    recipient,
                    False,
                    "SMTP connection ended before this email was sent.",
                )
            )

    return results


# =========================================================
# SEND BATCH
# =========================================================

@app.route(
    "/send-batch",
    methods=["POST"],
)
def send_batch():

    if not is_logged_in():

        return jsonify(
            {
                "message": "Authentication required."
            }
        ), 401

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):

        return jsonify(
            {
                "message": "Invalid request."
            }
        ), 400

    sender_name = str(
        data.get(
            "sender_name",
            "",
        )
    ).strip()

    gmail = str(
        data.get(
            "gmail",
            "",
        )
    ).strip().lower()

    app_password = str(
        data.get(
            "app_password",
            "",
        )
    ).strip()

    subject = str(
        data.get(
            "subject",
            "",
        )
    ).strip()

    body = data.get(
        "body",
        "",
    )

    is_html = bool(
        data.get(
            "is_html",
            False,
        )
    )

    recipients = clean_recipients(
        data.get(
            "recipients",
            [],
        )
    )

    turnstile_token = str(
        data.get(
            "turnstile_token",
            "",
        )
    ).strip()


    # =====================================================
    # VALIDATION
    # =====================================================

    if not sender_name:

        return jsonify(
            {
                "message": "Enter sender name."
            }
        ), 400


    if not is_valid_email(gmail):

        return jsonify(
            {
                "message": "Enter a valid Gmail address."
            }
        ), 400


    if not app_password:

        return jsonify(
            {
                "message": "Enter Google App Password."
            }
        ), 400


    if not subject:

        return jsonify(
            {
                "message": "Enter email subject."
            }
        ), 400


    if not isinstance(body, str) or not body.strip():

        return jsonify(
            {
                "message": "Enter message body."
            }
        ), 400


    if not recipients:

        return jsonify(
            {
                "message": "Add at least one valid recipient."
            }
        ), 400


    # =====================================================
    # TURNSTILE
    # =====================================================

    remote_ip = request.headers.get(
        "X-Forwarded-For",
        request.remote_addr,
    )

    if remote_ip and "," in remote_ip:
        remote_ip = remote_ip.split(",")[0].strip()


    if not verify_turnstile(
        turnstile_token,
        remote_ip,
    ):

        return jsonify(
            {
                "message": "Cloudflare verification failed."
            }
        ), 403


    # =====================================================
    # PREPARE MESSAGE FOR EVERY RECIPIENT
    # =====================================================

    jobs = []

    for recipient in recipients:

        try:

            message = build_message(
                sender_name=sender_name,
                gmail=gmail,
                recipient=recipient,
                subject=subject,
                body=body,
                is_html=is_html,
            )

            jobs.append(
                {
                    "recipient": recipient,
                    "message": message,
                }
            )

        except Exception as exc:

            return jsonify(
                {
                    "message": (
                        "Could not build email: "
                        f"{exc}"
                    )
                }
            ), 400


    total = len(jobs)


    # =====================================================
    # STREAMING RESPONSE
    # =====================================================

    @stream_with_context
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
                    "remaining": total,
                },
                ensure_ascii=False,
            )
            + "\n"
        )


        # -------------------------------------------------
        # SPLIT jobs into 2 worker batches.
        #
        # Example:
        # 12 emails -> worker 1 gets 6
        #           -> worker 2 gets 6
        #
        # Each worker keeps its SMTP connection open.
        # -------------------------------------------------

        worker_batches = [
            []
            for _ in range(
                min(
                    MAX_PARALLEL_SENDS,
                    total,
                )
            )
        ]


        for index, job in enumerate(jobs):

            worker_batches[
                index % len(worker_batches)
            ].append(job)


        # Remove empty batches just in case.
        worker_batches = [
            batch
            for batch in worker_batches
            if batch
        ]


        # -------------------------------------------------
        # Start only the configured number of workers.
        # -------------------------------------------------

        with ThreadPoolExecutor(
            max_workers=len(worker_batches),
            thread_name_prefix="smtp-worker",
        ) as executor:

            futures = []

            for batch in worker_batches:

                futures.append(
                    executor.submit(
                        smtp_worker,
                        gmail,
                        app_password,
                        batch,
                    )
                )


            # -------------------------------------------------
            # Read results as workers finish.
            # -------------------------------------------------

            for future in as_completed(
                futures
            ):

                try:

                    results = future.result()

                except Exception as exc:

                    # Unexpected worker-level failure.
                    results = []

                    failed += 1

                    yield (
                        json.dumps(
                            {
                                "type": "progress",
                                "total": total,
                                "sent": sent,
                                "failed": failed,
                                "remaining": max(
                                    0,
                                    total - sent - failed,
                                ),
                                "message": str(exc),
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                    continue


                for (
                    recipient,
                    success,
                    error_message,
                ) in results:

                    if success:

                        sent += 1

                    else:

                        failed += 1


                    remaining = max(
                        0,
                        total - sent - failed,
                    )


                    yield (
                        json.dumps(
                            {
                                "type": "progress",
                                "total": total,
                                "sent": sent,
                                "failed": failed,
                                "remaining": remaining,
                                "recipient": recipient,
                                "success": success,
                                "error": (
                                    error_message
                                    if not success
                                    else ""
                                ),
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )


        # =================================================
        # COMPLETE
        # =================================================

        if failed == 0:

            message = (
                "All emails were accepted by Gmail SMTP."
            )

        else:

            message = (
                f"Sending complete: "
                f"{sent} accepted, "
                f"{failed} failed."
            )


        yield (
            json.dumps(
                {
                    "type": "complete",
                    "total": total,
                    "sent": sent,
                    "failed": failed,
                    "remaining": max(
                        0,
                        total - sent - failed,
                    ),
                    "message": message,
                },
                ensure_ascii=False,
            )
            + "\n"
        )


    response = Response(
        generate(),
        mimetype="application/x-ndjson",
    )

    # Helps prevent buffering in compatible proxies.
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
# HEALTH CHECK
# =========================================================

@app.route("/health")
def health():

    return jsonify(
        {
            "status": "ok",
            "parallel_sends": MAX_PARALLEL_SENDS,
            "max_recipients": MAX_RECIPIENTS,
            "smtp": SMTP_HOST,
            "smtp_port": SMTP_PORT,
        }
    )


# =========================================================
# LOCAL DEVELOPMENT
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                "5000",
            )
        ),
        debug=False,
    )

import os
import re
import ssl
import time
import json
import queue
import secrets
import smtplib
import uuid

from datetime import datetime, timezone
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor

from flask import (
    Flask,
    request,
    session,
    redirect,
    jsonify,
    Response,
    render_template,
)

# =========================================================
# APP
# =========================================================

app = Flask(__name__)

app.secret_key = os.environ.get("SESSION_SECRET", "")

if not app.secret_key:
    raise RuntimeError("SESSION_SECRET is not configured in Vercel.")

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=3600,
)

# =========================================================
# VERCEL ENVIRONMENT VARIABLES
# =========================================================

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "").strip()

TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()

# Gmail SMTP credentials.
#
# IMPORTANT:
# These two variables must exist if this file is using Gmail SMTP.
# Do NOT put a normal Gmail account password here.
# Use the appropriate Gmail SMTP authentication credential
# (normally a Google App Password for SMTP).
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "").strip()

# =========================================================
# SETTINGS
# =========================================================

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# Small delay between individual messages per worker.
SEND_DELAY_SECONDS = 1.0

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


# =========================================================
# HELPERS
# =========================================================

def clean_header(value):
    """
    Prevent CR/LF header injection.
    """
    if value is None:
        return ""

    value = str(value)
    value = value.replace("\r", " ").replace("\n", " ")
    return " ".join(value.split()).strip()


def valid_email(email):
    if not email:
        return False

    email = email.strip()

    if len(email) > 254:
        return False

    return bool(EMAIL_RE.fullmatch(email))


def parse_recipients(value):
    """
    Accept:
      a@example.com
      a@example.com,b@example.com
      a@example.com; b@example.com
      one per line

    Removes duplicates.
    """

    if not isinstance(value, str):
        return []

    parts = re.split(r"[,;\n\r]+", value)

    result = []
    seen = set()

    for item in parts:
        email = item.strip().lower()

        if not email:
            continue

        if email in seen:
            continue

        seen.add(email)
        result.append(email)

    return result[:MAX_RECIPIENTS]


def split_recipients(recipients, workers=MAX_PARALLEL_SENDS):
    """
    Round-robin distribution so both workers get work.
    """
    chunks = [[] for _ in range(workers)]

    for index, recipient in enumerate(recipients):
        chunks[index % workers].append(recipient)

    return chunks


def spintax(text):
    """
    Supports:
        {Hello|Hi|Hey}

    This is normal content variation, not spam-filter bypass.
    """

    if not isinstance(text, str):
        return ""

    pattern = re.compile(r"\{([^{}]+)\}")

    while True:
        match = pattern.search(text)

        if not match:
            break

        choices = match.group(1).split("|")

        if len(choices) <= 1:
            break

        selected = secrets.choice(choices)

        text = (
            text[:match.start()]
            + selected
            + text[match.end():]
        )

    return text


def build_email(sender, recipient, subject, body):
    """
    Clean RFC-compatible plain-text email.
    """

    sender = clean_header(sender)
    recipient = clean_header(recipient)
    subject = clean_header(subject)

    msg = MIMEText(
        body,
        "plain",
        "utf-8",
    )

    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = datetime.now(
        timezone.utc
    ).strftime("%a, %d %b %Y %H:%M:%S +0000")

    msg["Message-ID"] = (
        f"<{uuid.uuid4().hex}@mail.local>"
    )

    msg["MIME-Version"] = "1.0"

    return msg


def smtp_error_message(exc):
    """
    Return a useful but non-sensitive SMTP error.
    """

    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return "SMTP authentication failed. Check Gmail SMTP credentials."

    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "SMTP recipient was refused."

    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "SMTP sender was refused."

    if isinstance(exc, smtplib.SMTPDataError):
        return "SMTP server rejected the message data."

    if isinstance(exc, smtplib.SMTPServerDisconnected):
        return "SMTP server disconnected."

    if isinstance(exc, TimeoutError):
        return "SMTP connection timed out."

    return str(exc)[:300] or exc.__class__.__name__


# =========================================================
# AUTHENTICATION
# =========================================================

def logged_in():
    return session.get("authenticated") is True


@app.before_request
def require_login():

    # These routes must remain accessible without login.
    public_endpoints = {
        "login",
        "health",
        "static",
    }

    if request.endpoint in public_endpoints:
        return None

    # Explicitly protect the application.
    if logged_in():
        return None

    # API requests receive JSON 401.
    if (
        request.path.startswith("/api/")
        or request.path == "/send-batch"
    ):
        return jsonify({
            "ok": False,
            "error": "Authentication required.",
            "login_required": True,
        }), 401

    return redirect("/login")


# =========================================================
# HEALTH
# =========================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "authenticated": logged_in(),
    })


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    # NEVER allow an empty LOGIN_PASSWORD to act as a valid
    # password.
    if not LOGIN_PASSWORD:
        return (
            "Server configuration error: LOGIN_PASSWORD is missing.",
            500,
        )

    if request.method == "GET":

        # Already authenticated.
        if logged_in():
            return redirect("/")

        return render_template(
            "login.html",
            turnstile_site_key=TURNSTILE_SITE_KEY,
        )

    # -----------------------------------------------------
    # POST
    # -----------------------------------------------------

    data = request.get_json(silent=True)

    if isinstance(data, dict):
        password = str(data.get("password", ""))
        turnstile_token = str(
            data.get("cf-turnstile-response", "")
            or data.get("turnstile_token", "")
        )
    else:
        password = request.form.get("password", "")
        turnstile_token = (
            request.form.get("cf-turnstile-response", "")
            or request.form.get("turnstile_token", "")
        )

    # Constant-time password comparison.
    password_ok = secrets.compare_digest(
        password,
        LOGIN_PASSWORD,
    )

    if not password_ok:
        return jsonify({
            "ok": False,
            "error": "Invalid password.",
        }), 401

    # -----------------------------------------------------
    # Optional Turnstile verification.
    #
    # If TURNSTILE_SECRET_KEY is configured, the token must
    # also be supplied and verified.
    # -----------------------------------------------------

    if TURNSTILE_SECRET_KEY:

        if not turnstile_token:
            return jsonify({
                "ok": False,
                "error": "Turnstile verification required.",
            }), 400

        try:
            import urllib.parse
            import urllib.request

            payload = urllib.parse.urlencode({
                "secret": TURNSTILE_SECRET_KEY,
                "response": turnstile_token,
                "remoteip": request.remote_addr or "",
            }).encode()

            req = urllib.request.Request(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data=payload,
                headers={
                    "Content-Type":
                        "application/x-www-form-urlencoded",
                },
                method="POST",
            )

            with urllib.request.urlopen(
                req,
                timeout=10,
            ) as response:

                verification = json.loads(
                    response.read().decode("utf-8")
                )

            if not verification.get("success"):
                return jsonify({
                    "ok": False,
                    "error": "Turnstile verification failed.",
                }), 403

        except Exception:
            return jsonify({
                "ok": False,
                "error": "Turnstile verification error.",
            }), 502

    # -----------------------------------------------------
    # Successful authentication
    # -----------------------------------------------------

    session.clear()
    session.permanent = True
    session["authenticated"] = True

    return jsonify({
        "ok": True,
        "message": "Login successful.",
    })


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout", methods=["GET", "POST"])
def logout():

    session.clear()

    if request.method == "POST":
        return jsonify({
            "ok": True,
        })

    return redirect("/login")


# =========================================================
# MAIN APP
# =========================================================

@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        turnstile_site_key=TURNSTILE_SITE_KEY,
    )


# =========================================================
# SMTP CONNECTION
# =========================================================

def create_smtp_connection():
    """
    Create a fresh Gmail SSL SMTP connection.
    """

    if not SMTP_USERNAME:
        raise RuntimeError(
            "SMTP_USERNAME is not configured."
        )

    if not SMTP_PASSWORD:
        raise RuntimeError(
            "SMTP_PASSWORD is not configured."
        )

    context = ssl.create_default_context()

    server = smtplib.SMTP_SSL(
        SMTP_HOST,
        SMTP_PORT,
        timeout=SMTP_TIMEOUT,
        context=context,
    )

    server.login(
        SMTP_USERNAME,
        SMTP_PASSWORD,
    )

    return server


# =========================================================
# SMTP WORKER
# =========================================================

def smtp_worker(
    worker_id,
    recipients,
    sender,
    subject,
    body,
    event_queue,
):
    """
    One worker handles its own SMTP connection.

    IMPORTANT:
    Every send result is pushed into event_queue immediately.
    This is what allows the frontend to display true
    one-by-one progress.
    """

    server = None

    try:

        event_queue.put({
            "type": "worker_started",
            "worker": worker_id,
        })

        # -------------------------------------------------
        # Open SMTP connection.
        # -------------------------------------------------

        try:
            server = create_smtp_connection()

        except Exception as exc:

            error_text = smtp_error_message(exc)

            # Mark ALL recipients assigned to this worker
            # as failed so the stream never gets stuck.
            for recipient in recipients:

                event_queue.put({
                    "type": "result",
                    "worker": worker_id,
                    "recipient": recipient,
                    "success": False,
                    "error": error_text,
                })

            return

        # -------------------------------------------------
        # Send messages one by one.
        # -------------------------------------------------

        for index, recipient in enumerate(recipients):

            # Delay between messages.
            if index > 0:
                time.sleep(SEND_DELAY_SECONDS)

            msg = None

            try:

                # Generate content independently for each
                # recipient.
                final_subject = spintax(subject)
                final_body = spintax(body)

                msg = build_email(
                    sender=sender,
                    recipient=recipient,
                    subject=final_subject,
                    body=final_body,
                )

                server.sendmail(
                    sender,
                    [recipient],
                    msg.as_string(),
                )

                # -------------------------------------------------
                # CRITICAL:
                # Send the result immediately after sendmail()
                # returns. Do NOT wait for the whole worker.
                # -------------------------------------------------

                event_queue.put({
                    "type": "result",
                    "worker": worker_id,
                    "recipient": recipient,
                    "success": True,
                })

            except smtplib.SMTPServerDisconnected as exc:

                # Connection status is uncertain.
                #
                # We intentionally DO NOT blindly retry sendmail()
                # because the SMTP server may already have accepted
                # the message and only the response got lost.
                event_queue.put({
                    "type": "result",
                    "worker": worker_id,
                    "recipient": recipient,
                    "success": False,
                    "error": (
                        "SMTP connection lost; "
                        "delivery status is unknown."
                    ),
                })

                # Stop this worker. The remaining recipients are
                # explicitly marked failed.
                for remaining in recipients[index + 1:]:

                    event_queue.put({
                        "type": "result",
                        "worker": worker_id,
                        "recipient": remaining,
                        "success": False,
                        "error": "SMTP connection unavailable.",
                    })

                break

            except (
                smtplib.SMTPConnectError,
                smtplib.SMTPServerDisconnected,
                TimeoutError,
                ConnectionError,
            ) as exc:

                error_text = smtp_error_message(exc)

                event_queue.put({
                    "type": "result",
                    "worker": worker_id,
                    "recipient": recipient,
                    "success": False,
                    "error": error_text,
                })

                for remaining in recipients[index + 1:]:

                    event_queue.put({
                        "type": "result",
                        "worker": worker_id,
                        "recipient": remaining,
                        "success": False,
                        "error": error_text,
                    })

                break

            except Exception as exc:

                event_queue.put({
                    "type": "result",
                    "worker": worker_id,
                    "recipient": recipient,
                    "success": False,
                    "error": smtp_error_message(exc),
                })

    finally:

        # -----------------------------------------------------
        # Always close SMTP connection.
        # -----------------------------------------------------

        if server is not None:

            try:
                server.quit()
            except Exception:
                try:
                    server.close()
                except Exception:
                    pass

        # -----------------------------------------------------
        # ALWAYS signal worker completion.
        # -----------------------------------------------------

        event_queue.put({
            "type": "worker_done",
            "worker": worker_id,
        })


# =========================================================
# SEND BATCH
# =========================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():

    # -----------------------------------------------------
    # Extra authentication check.
    #
    # Even though before_request already protects this route,
    # keep this check here as defense-in-depth.
    # -----------------------------------------------------

    if not logged_in():
        return jsonify({
            "ok": False,
            "error": "Authentication required.",
        }), 401

    # -----------------------------------------------------
    # SMTP configuration
    # -----------------------------------------------------

    if not SMTP_USERNAME:
        return jsonify({
            "ok": False,
            "error": "SMTP_USERNAME is not configured in Vercel.",
        }), 500

    if not SMTP_PASSWORD:
        return jsonify({
            "ok": False,
            "error": "SMTP_PASSWORD is not configured in Vercel.",
        }), 500

    # -----------------------------------------------------
    # JSON
    # -----------------------------------------------------

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "ok": False,
            "error": "Invalid JSON request.",
        }), 400

    # -----------------------------------------------------
    # Sender
    # -----------------------------------------------------

    sender = clean_header(
        data.get("sender", "")
    )

    if not sender:
        # Safer default: authenticated SMTP account.
        sender = SMTP_USERNAME

    if not valid_email(sender):
        return jsonify({
            "ok": False,
            "error": "Invalid sender email.",
        }), 400

    # -----------------------------------------------------
    # Recipients
    # -----------------------------------------------------

    recipients = parse_recipients(
        data.get("recipients", "")
    )

    if not recipients:
        return jsonify({
            "ok": False,
            "error": "No valid recipients found.",
        }), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify({
            "ok": False,
            "error": (
                f"Maximum {MAX_RECIPIENTS} recipients allowed."
            ),
        }), 400

    invalid = [
        email
        for email in recipients
        if not valid_email(email)
    ]

    if invalid:
        return jsonify({
            "ok": False,
            "error": "One or more recipient addresses are invalid.",
            "invalid": invalid,
        }), 400

    # -----------------------------------------------------
    # Subject
    # -----------------------------------------------------

    subject = clean_header(
        data.get("subject", "")
    )

    if not subject:
        return jsonify({
            "ok": False,
            "error": "Subject is required.",
        }), 400

    if len(subject) > 998:
        return jsonify({
            "ok": False,
            "error": "Subject is too long.",
        }), 400

    # -----------------------------------------------------
    # Body
    # -----------------------------------------------------

    body = data.get("body", "")

    if not isinstance(body, str):
        body = str(body)

    if not body.strip():
        return jsonify({
            "ok": False,
            "error": "Email body is required.",
        }), 400

    # -----------------------------------------------------
    # Split into exactly 2 workers where possible.
    # -----------------------------------------------------

    chunks = split_recipients(
        recipients,
        MAX_PARALLEL_SENDS,
    )

    chunks = [
        chunk
        for chunk in chunks
        if chunk
    ]

    total = len(recipients)

    event_queue = queue.Queue()

    # -----------------------------------------------------
    # Streaming generator
    # -----------------------------------------------------

    def generate():

        completed = 0
        successful = 0
        failed = 0
        workers_done = 0

        # Initial event.
        yield json.dumps({
            "type": "started",
            "total": total,
            "parallel": len(chunks),
        }) + "\n"

        executor = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        )

        futures = []

        try:

            # -------------------------------------------------
            # Start workers.
            # -------------------------------------------------

            for worker_number, chunk in enumerate(chunks, start=1):

                future = executor.submit(
                    smtp_worker,
                    worker_number,
                    chunk,
                    sender,
                    subject,
                    body,
                    event_queue,
                )

                futures.append(future)

            # -------------------------------------------------
            # Consume events immediately.
            # -------------------------------------------------

            while workers_done < len(chunks):

                try:
                    event = event_queue.get(
                        timeout=0.75
                    )

                except queue.Empty:

                    # Keepalive prevents idle buffering/timeouts.
                    yield json.dumps({
                        "type": "keepalive",
                        "completed": completed,
                        "total": total,
                    }) + "\n"

                    continue

                event_type = event.get("type")

                if event_type == "result":

                    completed += 1

                    if event.get("success"):
                        successful += 1
                    else:
                        failed += 1

                    # -----------------------------------------
                    # TRUE LIVE 1-BY-1 RESULT
                    # -----------------------------------------

                    yield json.dumps({
                        **event,
                        "completed": completed,
                        "successful": successful,
                        "failed": failed,
                        "total": total,
                    }) + "\n"

                elif event_type == "worker_started":

                    yield json.dumps(event) + "\n"

                elif event_type == "worker_done":

                    workers_done += 1

                    yield json.dumps({
                        **event,
                        "workers_done": workers_done,
                        "workers_total": len(chunks),
                    }) + "\n"

            # -------------------------------------------------
            # Safety:
            # If something went wrong and results are missing,
            # don't pretend they were successful.
            # -------------------------------------------------

            while completed < total:

                try:
                    event = event_queue.get_nowait()
                except queue.Empty:
                    break

                if event.get("type") == "result":

                    completed += 1

                    if event.get("success"):
                        successful += 1
                    else:
                        failed += 1

                    yield json.dumps({
                        **event,
                        "completed": completed,
                        "successful": successful,
                        "failed": failed,
                        "total": total,
                    }) + "\n"

            # -------------------------------------------------
            # Final event.
            # -------------------------------------------------

            yield json.dumps({
                "type": "finished",
                "completed": completed,
                "successful": successful,
                "failed": failed,
                "total": total,
            }) + "\n"

        finally:

            executor.shutdown(
                wait=False,
                cancel_futures=False,
            )

    # ---------------------------------------------------------
    # Streaming response
    # ---------------------------------------------------------

    response = Response(
        generate(),
        mimetype="application/x-ndjson",
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate, "
        "max-age=0"
    )

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    # Helps against buffering proxies.
    response.headers["X-Accel-Buffering"] = "no"

    response.headers["X-Content-Type-Options"] = "nosniff"

    return response


# =========================================================
# ERROR HANDLER
# =========================================================

@app.errorhandler(Exception)
def handle_exception(exc):

    # Do not expose internal stack traces to users.
    return jsonify({
        "ok": False,
        "error": "Internal server error.",
    }), 500


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

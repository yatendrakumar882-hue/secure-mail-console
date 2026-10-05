import os
import re
import ssl
import time
import uuid
import queue
import smtplib
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from email.header import Header
from email.utils import formataddr


# ============================================================
# APP
# ============================================================

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
    static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
)

app.secret_key = os.environ.get("SESSION_SECRET", "change-this-secret")


# ============================================================
# CONFIG
# ============================================================

MAX_RECIPIENTS = 25
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# Small delay per worker.
# With 2 workers, maximum concurrency remains 2.
SEND_DELAY_SECONDS = 1.0

LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

# Optional Turnstile.
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")


# ============================================================
# HELPERS
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def clean_header(value, max_length=998):
    """
    Prevent CR/LF header injection.
    """
    if value is None:
        return ""

    value = str(value)
    value = value.replace("\r", " ").replace("\n", " ")
    value = re.sub(r"\s+", " ", value).strip()

    return value[:max_length]


def valid_email(email):
    email = email.strip()
    return bool(EMAIL_RE.fullmatch(email))


def parse_recipients(raw):
    """
    Accept comma/newline/semicolon separated recipients.
    """
    if not raw:
        return []

    parts = re.split(r"[,;\n\r]+", raw)

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

    return result


def split_recipients(recipients, workers=2):
    """
    Round-robin distribution keeps the workload reasonably balanced.
    """
    chunks = [[] for _ in range(workers)]

    for index, recipient in enumerate(recipients):
        chunks[index % workers].append(recipient)

    return [chunk for chunk in chunks if chunk]


def spintax(text):
    """
    Simple {one|two|three} spintax.

    This is only for legitimate content variation and is intentionally
    limited to one level.
    """
    if not text:
        return ""

    pattern = re.compile(r"\{([^{}|]+(?:\|[^{}|]+)+)\}")

    def replace(match):
        choices = match.group(1).split("|")

        # Use SystemRandom so this isn't tied to predictable random state.
        import secrets
        return secrets.choice(choices).strip()

    return pattern.sub(replace, text)


def build_email(
    sender_name,
    sender_email,
    recipient,
    subject,
    body,
):
    """
    Build a normal RFC-compatible text email.
    """

    sender_name = clean_header(sender_name, 200)
    sender_email = clean_header(sender_email, 320)
    recipient = clean_header(recipient, 320)
    subject = clean_header(subject, 998)

    body = body or ""

    msg = MIMEText(body, "plain", "utf-8")

    if sender_name:
        msg["From"] = formataddr(
            (
                str(Header(sender_name, "utf-8")),
                sender_email,
            )
        )
    else:
        msg["From"] = sender_email

    msg["To"] = recipient
    msg["Subject"] = str(Header(subject, "utf-8"))

    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid()
    msg["MIME-Version"] = "1.0"

    return msg


# ============================================================
# AUTH
# ============================================================

def logged_in():
    return bool(session.get("authenticated"))


@app.before_request
def require_login():
    allowed = {
        "login",
        "static",
        "health",
    }

    endpoint = request.endpoint

    if endpoint in allowed:
        return None

    if not logged_in():
        if request.path.startswith("/api/") or request.path == "/send-batch":
            return jsonify(
                {
                    "ok": False,
                    "error": "Authentication required.",
                }
            ), 401

        return redirect(url_for("login"))

    return None


# ============================================================
# ROUTES
# ============================================================

@app.route("/health")
def health():
    return jsonify(
        {
            "ok": True,
            "service": "mail-sender",
        }
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if logged_in():
            return redirect(url_for("index"))

        return render_template("index.html", login_page=True)

    password = request.form.get("password", "")

    if not LOGIN_PASSWORD:
        return jsonify(
            {
                "ok": False,
                "error": "LOGIN_PASSWORD is not configured.",
            }
        ), 500

    if password != LOGIN_PASSWORD:
        return jsonify(
            {
                "ok": False,
                "error": "Invalid password.",
            }
        ), 401

    session["authenticated"] = True

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def index():
    return render_template("index.html", login_page=False)


# ============================================================
# SMTP WORKER
# ============================================================

def smtp_worker(
    recipients,
    event_queue,
    sender_name,
    sender_email,
    subject,
    body,
):
    """
    One worker = one SMTP connection.

    IMPORTANT:
    Each recipient produces an event immediately after sendmail()
    succeeds/fails. Nothing is accumulated for future.result().
    """

    worker_id = str(uuid.uuid4())[:8]

    server = None

    try:
        context = ssl.create_default_context()

        server = smtplib.SMTP_SSL(
            SMTP_HOST,
            SMTP_PORT,
            timeout=SMTP_TIMEOUT,
            context=context,
        )

        server.ehlo()

        server.login(
            SMTP_USERNAME,
            SMTP_PASSWORD,
        )

        event_queue.put(
            {
                "type": "worker_started",
                "worker": worker_id,
            }
        )

        for index, recipient in enumerate(recipients):
            # Delay between messages from this worker.
            if index > 0 and SEND_DELAY_SECONDS > 0:
                time.sleep(SEND_DELAY_SECONDS)

            try:
                message = build_email(
                    sender_name=sender_name,
                    sender_email=sender_email,
                    recipient=recipient,
                    subject=spintax(subject),
                    body=spintax(body),
                )

                refused = server.sendmail(
                    sender_email,
                    [recipient],
                    message.as_string(),
                )

                # sendmail() returns refused recipients.
                if refused:
                    error_text = str(refused)

                    event_queue.put(
                        {
                            "type": "result",
                            "success": False,
                            "recipient": recipient,
                            "error": error_text,
                            "worker": worker_id,
                        }
                    )
                else:
                    event_queue.put(
                        {
                            "type": "result",
                            "success": True,
                            "recipient": recipient,
                            "error": None,
                            "worker": worker_id,
                        }
                    )

            except (smtplib.SMTPServerDisconnected, ConnectionError, OSError) as exc:
                # Try to reconnect once for this worker.
                error_text = str(exc) or exc.__class__.__name__

                try:
                    if server is not None:
                        try:
                            server.quit()
                        except Exception:
                            pass

                    server = smtplib.SMTP_SSL(
                        SMTP_HOST,
                        SMTP_PORT,
                        timeout=SMTP_TIMEOUT,
                        context=context,
                    )

                    server.ehlo()
                    server.login(
                        SMTP_USERNAME,
                        SMTP_PASSWORD,
                    )

                    # Retry the same recipient once after reconnect.
                    message = build_email(
                        sender_name=sender_name,
                        sender_email=sender_email,
                        recipient=recipient,
                        subject=spintax(subject),
                        body=spintax(body),
                    )

                    refused = server.sendmail(
                        sender_email,
                        [recipient],
                        message.as_string(),
                    )

                    if refused:
                        event_queue.put(
                            {
                                "type": "result",
                                "success": False,
                                "recipient": recipient,
                                "error": str(refused),
                                "worker": worker_id,
                            }
                        )
                    else:
                        event_queue.put(
                            {
                                "type": "result",
                                "success": True,
                                "recipient": recipient,
                                "error": None,
                                "worker": worker_id,
                                "retried": True,
                            }
                        )

                except Exception as retry_exc:
                    event_queue.put(
                        {
                            "type": "result",
                            "success": False,
                            "recipient": recipient,
                            "error": (
                                f"SMTP connection error: "
                                f"{retry_exc}"
                            ),
                            "worker": worker_id,
                        }
                    )

            except smtplib.SMTPException as exc:
                event_queue.put(
                    {
                        "type": "result",
                        "success": False,
                        "recipient": recipient,
                        "error": str(exc) or exc.__class__.__name__,
                        "worker": worker_id,
                    }
                )

            except Exception as exc:
                event_queue.put(
                    {
                        "type": "result",
                        "success": False,
                        "recipient": recipient,
                        "error": str(exc) or exc.__class__.__name__,
                        "worker": worker_id,
                    }
                )

        event_queue.put(
            {
                "type": "worker_done",
                "worker": worker_id,
            }
        )

    except smtplib.SMTPException as exc:
        event_queue.put(
            {
                "type": "worker_error",
                "worker": worker_id,
                "error": str(exc) or exc.__class__.__name__,
            }
        )

    except Exception as exc:
        event_queue.put(
            {
                "type": "worker_error",
                "worker": worker_id,
                "error": str(exc) or exc.__class__.__name__,
            }
        )

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass


# ============================================================
# BATCH SEND
# ============================================================

@app.route("/send-batch", methods=["POST"])
def send_batch():
    """
    Streams NDJSON events.

    Example:
      {"type":"started","total":10}
      {"type":"result","success":true,"recipient":"a@example.com"}
      {"type":"result","success":true,"recipient":"b@example.com"}
      ...
      {"type":"finished",...}
    """

    if not SMTP_USERNAME or not SMTP_PASSWORD:
        return jsonify(
            {
                "ok": False,
                "error": "SMTP_USERNAME or SMTP_PASSWORD is not configured.",
            }
        ), 500

    data = request.get_json(silent=True)

    if not data:
        return jsonify(
            {
                "ok": False,
                "error": "Invalid JSON request.",
            }
        ), 400

    raw_recipients = data.get("recipients", "")

    sender_name = clean_header(
        data.get("sender_name", ""),
        200,
    )

    sender_email = clean_header(
        data.get("sender_email") or SMTP_USERNAME,
        320,
    )

    subject = clean_header(
        data.get("subject", ""),
        998,
    )

    body = data.get("body", "")

    if not isinstance(body, str):
        body = str(body)

    if not sender_email or not valid_email(sender_email):
        return jsonify(
            {
                "ok": False,
                "error": "Invalid sender email.",
            }
        ), 400

    recipients = parse_recipients(raw_recipients)

    if not recipients:
        return jsonify(
            {
                "ok": False,
                "error": "No recipients supplied.",
            }
        ), 400

    if len(recipients) > MAX_RECIPIENTS:
        return jsonify(
            {
                "ok": False,
                "error": (
                    f"Maximum {MAX_RECIPIENTS} recipients are allowed "
                    "per batch."
                ),
            }
        ), 400

    invalid = [
        email
        for email in recipients
        if not valid_email(email)
    ]

    if invalid:
        return jsonify(
            {
                "ok": False,
                "error": "Invalid recipient email(s).",
                "invalid": invalid,
            }
        ), 400

    if not subject.strip():
        return jsonify(
            {
                "ok": False,
                "error": "Subject is required.",
            }
        ), 400

    if not body.strip():
        return jsonify(
            {
                "ok": False,
                "error": "Message body is required.",
            }
        ), 400

    event_queue = queue.Queue()

    chunks = split_recipients(
        recipients,
        MAX_PARALLEL_SENDS,
    )

    total_workers = len(chunks)

    def stream():
        executor = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        )

        futures = []

        completed = 0
        successful = 0
        failed = 0
        worker_finished = 0

        try:
            # Send initial event immediately.
            yield (
                jsonify(
                    {
                        "type": "started",
                        "total": len(recipients),
                        "workers": total_workers,
                    }
                ).get_data(as_text=True).strip()
                + "\n"
            )

            for chunk in chunks:
                future = executor.submit(
                    smtp_worker,
                    chunk,
                    event_queue,
                    sender_name,
                    sender_email,
                    subject,
                    body,
                )

                futures.append(future)

            while worker_finished < total_workers:
                try:
                    event = event_queue.get(timeout=1.0)

                except queue.Empty:
                    # Keep connection alive while SMTP is working.
                    yield (
                        '{"type":"keepalive"}\n'
                    )
                    continue

                event_type = event.get("type")

                if event_type == "result":
                    completed += 1

                    if event.get("success"):
                        successful += 1
                    else:
                        failed += 1

                    event["completed"] = completed
                    event["successful"] = successful
                    event["failed"] = failed
                    event["total"] = len(recipients)

                    # THIS is the important part:
                    # every result is yielded immediately.
                    import json

                    yield (
                        json.dumps(
                            event,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                elif event_type == "worker_done":
                    worker_finished += 1

                    import json

                    yield (
                        json.dumps(
                            event,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                elif event_type == "worker_started":
                    import json

                    yield (
                        json.dumps(
                            event,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                elif event_type == "worker_error":
                    worker_finished += 1

                    import json

                    yield (
                        json.dumps(
                            event,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

            import json

            final_event = {
                "type": "finished",
                "ok": failed == 0,
                "total": len(recipients),
                "completed": completed,
                "successful": successful,
                "failed": failed,
            }

            yield (
                json.dumps(
                    final_event,
                    ensure_ascii=False,
                )
                + "\n"
            )

        except GeneratorExit:
            # Browser disconnected.
            for future in futures:
                future.cancel()

        except Exception as exc:
            import json

            yield (
                json.dumps(
                    {
                        "type": "stream_error",
                        "error": str(exc) or exc.__class__.__name__,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

        finally:
            executor.shutdown(
                wait=False,
                cancel_futures=True,
            )

    response = Response(
        stream(),
        mimetype="application/x-ndjson",
    )

    response.headers["Cache-Control"] = (
        "no-cache, no-store, must-revalidate"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    # Helps with proxies that support this header.
    response.headers["X-Accel-Buffering"] = "no"

    return response


# ============================================================
# ERROR HANDLER
# ============================================================

@app.errorhandler(Exception)
def handle_exception(exc):
    app.logger.exception("Unhandled error")

    if request.path == "/send-batch":
        return jsonify(
            {
                "ok": False,
                "error": "Internal server error.",
            }
        ), 500

    return (
        "Internal server error.",
        500,
    )


# ============================================================
# VERCEL
# ============================================================

# Vercel's Python runtime can discover the Flask `app` object.
# Local development:
#
#   python api/index.py
#
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
        threaded=True,
    )

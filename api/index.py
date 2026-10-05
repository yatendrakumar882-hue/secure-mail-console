import os
import re
import ssl
import time
import uuid
import json
import queue
import secrets
import smtplib

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
from email.header import Header
from email.utils import formataddr, formatdate, make_msgid


# ============================================================
# APP
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

# IMPORTANT:
# Put SESSION_SECRET in Vercel Environment Variables.
app.secret_key = os.environ.get(
    "SESSION_SECRET",
    "change-this-secret-in-vercel",
)


# ============================================================
# CONFIG
# ============================================================

MAX_RECIPIENTS = 25

# Exactly 2 concurrent SMTP workers.
MAX_PARALLEL_SENDS = 2

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_TIMEOUT = 25

# Small delay between messages handled by the SAME worker.
SEND_DELAY_SECONDS = 1.0

# Reconnect attempts after a connection problem.
MAX_RECONNECT_ATTEMPTS = 1


# ============================================================
# VERCEL ENVIRONMENT VARIABLES
# ============================================================

# Login password is taken ONLY from Vercel environment.
LOGIN_PASSWORD = os.environ.get("LOGIN_PASSWORD", "")

# Gmail SMTP credentials.
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

# Optional:
# Kept here so your existing environment does not break.
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "")


# ============================================================
# EMAIL VALIDATION
# ============================================================

EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def valid_email(email):
    if not email:
        return False

    email = email.strip()

    return bool(EMAIL_RE.fullmatch(email))


# ============================================================
# HEADER CLEANING
# ============================================================

def clean_header(value, max_length=998):
    """
    Remove CR/LF so user input cannot inject additional headers.
    """

    if value is None:
        return ""

    value = str(value)

    value = value.replace("\r", " ")
    value = value.replace("\n", " ")

    value = re.sub(r"\s+", " ", value).strip()

    return value[:max_length]


# ============================================================
# RECIPIENT PARSING
# ============================================================

def parse_recipients(raw):
    """
    Supports:

        a@example.com
        b@example.com

    or:

        a@example.com,b@example.com

    or semicolon separated.
    """

    if not raw:
        return []

    parts = re.split(
        r"[,;\n\r]+",
        str(raw),
    )

    recipients = []
    seen = set()

    for item in parts:

        email = item.strip().lower()

        if not email:
            continue

        if email in seen:
            continue

        seen.add(email)

        recipients.append(email)

    return recipients


# ============================================================
# SPLIT INTO 2 WORKERS
# ============================================================

def split_recipients(recipients, workers=2):
    """
    Round-robin distribution.

    Example:

    Worker 1:
      1, 3, 5, 7...

    Worker 2:
      2, 4, 6, 8...
    """

    workers = max(
        1,
        min(workers, len(recipients)),
    )

    chunks = [
        []
        for _ in range(workers)
    ]

    for index, recipient in enumerate(recipients):

        chunks[index % workers].append(
            recipient
        )

    return [
        chunk
        for chunk in chunks
        if chunk
    ]


# ============================================================
# SPINTAX
# ============================================================

def spintax(text):
    """
    Supports simple:

        Hello {friend|there|customer}

    This is intended for legitimate message variation.
    """

    if not text:
        return ""

    pattern = re.compile(
        r"\{([^{}|]+(?:\|[^{}|]+)+)\}"
    )

    def replace(match):

        choices = match.group(1).split("|")

        return secrets.choice(
            choices
        ).strip()

    return pattern.sub(
        replace,
        text,
    )


# ============================================================
# EMAIL BUILDER
# ============================================================

def build_email(
    sender_name,
    sender_email,
    recipient,
    subject,
    body,
):
    """
    Creates a standard text/plain MIME email.
    """

    sender_name = clean_header(
        sender_name,
        200,
    )

    sender_email = clean_header(
        sender_email,
        320,
    )

    recipient = clean_header(
        recipient,
        320,
    )

    subject = clean_header(
        subject,
        998,
    )

    body = str(body or "")

    msg = MIMEText(
        body,
        "plain",
        "utf-8",
    )

    # --------------------------------------------------------
    # FROM
    # --------------------------------------------------------

    if sender_name:

        msg["From"] = formataddr(
            (
                str(
                    Header(
                        sender_name,
                        "utf-8",
                    )
                ),
                sender_email,
            )
        )

    else:

        msg["From"] = sender_email

    # --------------------------------------------------------
    # STANDARD HEADERS
    # --------------------------------------------------------

    msg["To"] = recipient

    msg["Subject"] = str(
        Header(
            subject,
            "utf-8",
        )
    )

    msg["Date"] = formatdate(
        localtime=False
    )

    msg["Message-ID"] = make_msgid()

    msg["MIME-Version"] = "1.0"

    return msg


# ============================================================
# AUTH HELPERS
# ============================================================

def logged_in():
    return bool(
        session.get(
            "authenticated",
            False,
        )
    )


# ============================================================
# LOGIN PROTECTION
# ============================================================

@app.before_request
def require_login():

    allowed_endpoints = {
        "login",
        "static",
        "health",
    }

    endpoint = request.endpoint

    if endpoint in allowed_endpoints:
        return None

    if logged_in():
        return None

    # API/send endpoint should return JSON rather than
    # redirecting the fetch request to HTML.
    if (
        request.path.startswith("/api/")
        or request.path == "/send-batch"
    ):
        return jsonify(
            {
                "ok": False,
                "error": "Authentication required.",
            }
        ), 401

    return redirect(
        url_for("login")
    )


# ============================================================
# HEALTH
# ============================================================

@app.route("/health")
def health():

    return jsonify(
        {
            "ok": True,
            "service": "mail-sender",
        }
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"],
)
def login():

    # --------------------------------------------------------
    # GET
    # --------------------------------------------------------

    if request.method == "GET":

        if logged_in():

            return redirect(
                url_for("index")
            )

        return render_template(
            "index.html",
            login_page=True,
        )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    password = request.form.get(
        "password",
        "",
    )

    if not LOGIN_PASSWORD:

        return jsonify(
            {
                "ok": False,
                "error": (
                    "LOGIN_PASSWORD is not configured "
                    "in Vercel Environment Variables."
                ),
            }
        ), 500

    # Constant-time comparison.
    if not secrets.compare_digest(
        password,
        LOGIN_PASSWORD,
    ):

        return jsonify(
            {
                "ok": False,
                "error": "Invalid password.",
            }
        ), 401

    session.clear()

    session["authenticated"] = True

    return redirect(
        url_for("index")
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# MAIN PAGE
# ============================================================

@app.route("/")
def index():

    return render_template(
        "index.html",
        login_page=False,
    )


# ============================================================
# SMTP CONNECTION
# ============================================================

def create_smtp_connection():

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

    return server


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
    IMPORTANT:

    Every recipient generates a Queue event immediately
    after SMTP sendmail() returns.

    The worker DOES NOT wait until the entire batch finishes.
    """

    worker_id = str(
        uuid.uuid4()
    )[:8]

    server = None

    try:

        # ----------------------------------------------------
        # OPEN SMTP CONNECTION
        # ----------------------------------------------------

        server = create_smtp_connection()

        event_queue.put(
            {
                "type": "worker_started",
                "worker": worker_id,
            }
        )

        # ----------------------------------------------------
        # PROCESS RECIPIENTS
        # ----------------------------------------------------

        for index, recipient in enumerate(
            recipients
        ):

            # Small delay between messages handled
            # by this particular worker.
            if (
                index > 0
                and SEND_DELAY_SECONDS > 0
            ):

                time.sleep(
                    SEND_DELAY_SECONDS
                )

            # ------------------------------------------------
            # SEND ONE EMAIL
            # ------------------------------------------------

            success = False
            error_text = None
            retried = False

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

                if refused:

                    error_text = str(
                        refused
                    )

                else:

                    success = True

            # ------------------------------------------------
            # CONNECTION FAILURE
            # ------------------------------------------------

            except (
                smtplib.SMTPServerDisconnected,
                ConnectionError,
                OSError,
            ) as exc:

                error_text = (
                    str(exc)
                    or exc.__class__.__name__
                )

                # --------------------------------------------
                # ONE CONTROLLED RECONNECT
                # --------------------------------------------

                for attempt in range(
                    MAX_RECONNECT_ATTEMPTS
                ):

                    try:

                        if server is not None:

                            try:
                                server.quit()
                            except Exception:
                                pass

                        server = create_smtp_connection()

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

                        retried = True

                        if refused:

                            error_text = str(
                                refused
                            )

                        else:

                            success = True
                            error_text = None

                        break

                    except (
                        smtplib.SMTPServerDisconnected,
                        ConnectionError,
                        OSError,
                        smtplib.SMTPException,
                    ) as retry_exc:

                        error_text = (
                            str(retry_exc)
                            or retry_exc.__class__.__name__
                        )

            # ------------------------------------------------
            # SMTP ERROR
            # ------------------------------------------------

            except smtplib.SMTPException as exc:

                error_text = (
                    str(exc)
                    or exc.__class__.__name__
                )

            # ------------------------------------------------
            # ANY OTHER ERROR
            # ------------------------------------------------

            except Exception as exc:

                error_text = (
                    str(exc)
                    or exc.__class__.__name__
                )

            # ------------------------------------------------
            # LIVE EVENT
            # ------------------------------------------------
            #
            # THIS happens after EACH individual email.
            #
            # Browser doesn't have to wait for the worker.
            # ------------------------------------------------

            event_queue.put(
                {
                    "type": "result",
                    "success": success,
                    "recipient": recipient,
                    "error": error_text,
                    "worker": worker_id,
                    "retried": retried,
                }
            )

        # ----------------------------------------------------
        # WORKER COMPLETE
        # ----------------------------------------------------

        event_queue.put(
            {
                "type": "worker_done",
                "worker": worker_id,
            }
        )

    # ========================================================
    # LOGIN / INITIAL SMTP FAILURE
    # ========================================================

    except smtplib.SMTPException as exc:

        error_text = (
            str(exc)
            or exc.__class__.__name__
        )

        # Mark every recipient that this worker couldn't
        # process as failed so final counters remain accurate.
        for recipient in recipients:

            event_queue.put(
                {
                    "type": "result",
                    "success": False,
                    "recipient": recipient,
                    "error": error_text,
                    "worker": worker_id,
                }
            )

        event_queue.put(
            {
                "type": "worker_done",
                "worker": worker_id,
            }
        )

    except Exception as exc:

        error_text = (
            str(exc)
            or exc.__class__.__name__
        )

        for recipient in recipients:

            event_queue.put(
                {
                    "type": "result",
                    "success": False,
                    "recipient": recipient,
                    "error": error_text,
                    "worker": worker_id,
                }
            )

        event_queue.put(
            {
                "type": "worker_done",
                "worker": worker_id,
            }
        )

    # ========================================================
    # CLOSE SMTP CONNECTION
    # ========================================================

    finally:

        if server is not None:

            try:
                server.quit()
            except Exception:
                pass


# ============================================================
# SEND BATCH
# ============================================================

@app.route(
    "/send-batch",
    methods=["POST"],
)
def send_batch():

    # --------------------------------------------------------
    # SMTP CONFIG CHECK
    # --------------------------------------------------------

    if not SMTP_USERNAME:

        return jsonify(
            {
                "ok": False,
                "error": (
                    "SMTP_USERNAME is not configured."
                ),
            }
        ), 500

    if not SMTP_PASSWORD:

        return jsonify(
            {
                "ok": False,
                "error": (
                    "SMTP_PASSWORD is not configured."
                ),
            }
        ), 500

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    data = request.get_json(
        silent=True
    )

    if not data:

        return jsonify(
            {
                "ok": False,
                "error": "Invalid JSON request.",
            }
        ), 400

    # --------------------------------------------------------
    # INPUT
    # --------------------------------------------------------

    raw_recipients = data.get(
        "recipients",
        "",
    )

    sender_name = clean_header(
        data.get(
            "sender_name",
            "",
        ),
        200,
    )

    # For reliable authenticated sending, default to the
    # authenticated SMTP account.
    sender_email = clean_header(
        data.get(
            "sender_email"
        )
        or SMTP_USERNAME,
        320,
    )

    subject = clean_header(
        data.get(
            "subject",
            "",
        ),
        998,
    )

    body = data.get(
        "body",
        "",
    )

    if not isinstance(
        body,
        str,
    ):
        body = str(body)

    # --------------------------------------------------------
    # SENDER
    # --------------------------------------------------------

    if not valid_email(
        sender_email
    ):

        return jsonify(
            {
                "ok": False,
                "error": "Invalid sender email.",
            }
        ), 400

    # --------------------------------------------------------
    # RECIPIENTS
    # --------------------------------------------------------

    recipients = parse_recipients(
        raw_recipients
    )

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
                    f"Maximum {MAX_RECIPIENTS} "
                    "recipients are allowed per batch."
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

    # --------------------------------------------------------
    # SUBJECT
    # --------------------------------------------------------

    if not subject.strip():

        return jsonify(
            {
                "ok": False,
                "error": "Subject is required.",
            }
        ), 400

    # --------------------------------------------------------
    # BODY
    # --------------------------------------------------------

    if not body.strip():

        return jsonify(
            {
                "ok": False,
                "error": "Message body is required.",
            }
        ), 400

    # --------------------------------------------------------
    # QUEUE
    # --------------------------------------------------------

    event_queue = queue.Queue()

    # --------------------------------------------------------
    # 2 WORKERS
    # --------------------------------------------------------

    chunks = split_recipients(
        recipients,
        MAX_PARALLEL_SENDS,
    )

    total_workers = len(chunks)

    # ========================================================
    # STREAM GENERATOR
    # ========================================================

    def stream():

        executor = ThreadPoolExecutor(
            max_workers=MAX_PARALLEL_SENDS
        )

        futures = []

        completed = 0
        successful = 0
        failed = 0

        worker_finished = 0

        total = len(recipients)

        try:

            # ------------------------------------------------
            # FIRST EVENT
            # ------------------------------------------------

            yield (
                json.dumps(
                    {
                        "type": "started",
                        "total": total,
                        "workers": total_workers,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )

            # ------------------------------------------------
            # START WORKERS
            # ------------------------------------------------

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

                futures.append(
                    future
                )

            # ------------------------------------------------
            # READ EVENTS LIVE
            # ------------------------------------------------

            while (
                worker_finished
                < total_workers
            ):

                try:

                    event = event_queue.get(
                        timeout=1.0
                    )

                except queue.Empty:

                    # Keep HTTP connection alive.
                    yield (
                        '{"type":"keepalive"}\n'
                    )

                    continue

                event_type = event.get(
                    "type"
                )

                # ============================================
                # ONE EMAIL RESULT
                # ============================================

                if event_type == "result":

                    completed += 1

                    if event.get(
                        "success",
                        False,
                    ):

                        successful += 1

                    else:

                        failed += 1

                    event["completed"] = completed
                    event["successful"] = successful
                    event["failed"] = failed
                    event["total"] = total

                    # ----------------------------------------
                    # IMMEDIATELY SEND TO BROWSER
                    # ----------------------------------------

                    yield (
                        json.dumps(
                            event,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                # ============================================
                # WORKER START
                # ============================================

                elif event_type == "worker_started":

                    yield (
                        json.dumps(
                            event,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

                # ============================================
                # WORKER DONE
                # ============================================

                elif event_type == "worker_done":

                    worker_finished += 1

                    yield (
                        json.dumps(
                            event,
                            ensure_ascii=False,
                        )
                        + "\n"
                    )

            # ------------------------------------------------
            # FINAL RESULT
            # ------------------------------------------------

            final_event = {
                "type": "finished",
                "ok": (
                    failed == 0
                    and completed == total
                ),
                "total": total,
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

            # Browser closed/disconnected.
            for future in futures:

                future.cancel()

        except Exception as exc:

            yield (
                json.dumps(
                    {
                        "type": "stream_error",
                        "error": (
                            str(exc)
                            or exc.__class__.__name__
                        ),
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

    # ========================================================
    # RESPONSE
    # ========================================================

    response = Response(
        stream(),
        mimetype="application/x-ndjson",
    )

    # Disable caching.
    response.headers[
        "Cache-Control"
    ] = "no-cache, no-store, must-revalidate"

    response.headers[
        "Pragma"
    ] = "no-cache"

    response.headers[
        "Expires"
    ] = "0"

    # Helpful for reverse proxies.
    response.headers[
        "X-Accel-Buffering"
    ] = "no"

    return response


# ============================================================
# ERROR HANDLER
# ============================================================

@app.errorhandler(Exception)
def handle_exception(exc):

    app.logger.exception(
        "Unhandled application error"
    )

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
# LOCAL DEVELOPMENT
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000,
            )
        ),
        debug=False,
        threaded=True,
    )

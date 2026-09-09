const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "15mb" }));
app.use(express.urlencoded({ extended: true, limit: "15mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname)));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// 1. Password Route (@##)
const APP_PASSWORD_KEY = process.env.ACCESS_PASSWORD || "@##";
app.post(["/api/login", "/api/auth", "/login", "/auth"], (req, res) => {
  const { password } = req.body;
  if (password === APP_PASSWORD_KEY) {
    return res.json({ success: true, token: "authorized_session_token" });
  }
  return res.status(401).json({ success: false, message: "Invalid password" });
});

// Helper: Target cleaning
function sanitizeEmail(email) {
  if (!email) return "";
  return email
    .replace(/^[^a-zA-Z0-9]+/, "") // Shuruwat ke '-' ya bullet points hatayega
    .replace(/@gnoil\.com$/i, "@gmail.com")
    .replace(/@gmai1\.com$/i, "@gmail.com")
    .replace(/@gmail\.c$/i, "@gmail.com")
    .trim();
}

// 2. Dual Transporter (Proxy -> Direct Fallback)
function getTransporter(user, pass, withProxy = true) {
  const proxyUrl = process.env.PROXY_URL;
  const agent = withProxy && proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: sanitizeEmail(user),
      pass: pass.trim().replace(/\s+/g, ""),
    },
    ...(agent && {
      agent: agent,
      proxy: proxyUrl,
    }),
    connectionTimeout: 8000,
    greetingTimeout: 8000,
    socketTimeout: 8000,
  });
}

// 3. Robust Stream Handler
app.all(
  ["/api/send-stream", "/api/send", "/api/send-batch", "/send", "/send-stream"],
  async (req, res) => {
    const data = req.method === "POST" ? req.body : req.query;
    let {
      senderEmail,
      appPassword,
      recipients,
      to,
      subject,
      bodyText,
      message,
      htmlContent,
      senderName,
    } = data;

    senderEmail = sanitizeEmail(senderEmail);

    let list = [];
    if (Array.isArray(recipients)) {
      list = recipients;
    } else if (typeof recipients === "string") {
      list = recipients.split(/[\r\n,;]+/);
    } else if (to) {
      list = Array.isArray(to) ? to : [to];
    }

    const cleanRecipients = list
      .map((e) => sanitizeEmail(e))
      .filter((e) => e && e.includes("@") && e.includes("."));

    // SSE Stream headers init
    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    if (res.flushHeaders) res.flushHeaders();

    const writeStream = (event, payload) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
      if (res.flush) res.flush();
    };

    if (!senderEmail || !appPassword || cleanRecipients.length === 0) {
      writeStream("failed", {
        error: "Missing credentials or no valid recipient addresses.",
      });
      res.end();
      return;
    }

    // Stream Start Ping
    writeStream("start", { total: cleanRecipients.length });

    let activeTransporter = getTransporter(senderEmail, appPassword, true);
    const BATCH_SIZE = 6;
    const currentBatch = cleanRecipients.slice(0, BATCH_SIZE);

    for (let i = 0; i < currentBatch.length; i++) {
      const email = currentBatch[i];

      const mailOptions = {
        from: `"${senderName || "Notification"}" <${senderEmail}>`,
        to: email,
        subject: subject || "System Notification",
        text: bodyText || message || "Please review the information.",
        ...(htmlContent && { html: htmlContent }),
        headers: {
          "X-Priority": "3",
          "X-Mailer": "Microsoft Outlook 16.0",
          "Message-ID": `<${Date.now()}.${Math.random().toString(36).substring(2, 9)}@gmail.com>`,
        },
      };

      try {
        const info = await activeTransporter.sendMail(mailOptions);
        writeStream("sent", {
          email,
          status: "Sent",
          id: info.messageId,
          sent: i + 1,
          remaining: currentBatch.length - (i + 1),
        });
      } catch (proxyError) {
        // Proxy timeout/drop par direct fallback
        try {
          const directTransporter = getTransporter(senderEmail, appPassword, false);
          const info = await directTransporter.sendMail(mailOptions);
          writeStream("sent", {
            email,
            status: "Sent",
            id: info.messageId,
            sent: i + 1,
            remaining: currentBatch.length - (i + 1),
          });
        } catch (directError) {
          writeStream("failed", {
            email,
            error: directError.message,
            failed: 1,
          });
        }
      }

      // Fast pacing: 300ms
      if (i < currentBatch.length - 1) {
        await sleep(300);
      }
    }

    writeStream("complete", { status: "Dispatch completed" });
    res.end();
  }
);

// Cloudflare dummy verify endpoint
app.post("/api/verify-turnstile", (req, res) => {
  res.json({ success: true });
});

// UI routing
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, "index.html"));
    }
  });
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`Server running on ${PORT}`));
}

module.exports = app;

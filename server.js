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

// 1. Password Verification (@##)
const APP_PASSWORD_KEY = process.env.ACCESS_PASSWORD || "@##";
app.post(["/api/login", "/api/auth", "/login", "/auth"], (req, res) => {
  const { password } = req.body;
  if (password === APP_PASSWORD_KEY) {
    return res.json({ success: true, token: "authorized_token_xyz" });
  }
  return res.status(401).json({ success: false, message: "Invalid password" });
});

// Helper: Fix accidental typos automatically
function sanitizeEmail(email) {
  if (!email) return "";
  return email
    .trim()
    .replace(/^[^a-zA-Z0-9]+/, "")
    .replace(/@gnoil\.com$/i, "@gmail.com")
    .replace(/@gmai1\.com$/i, "@gmail.com")
    .replace(/@gmail\.c$/i, "@gmail.com");
}

// 2. Safe Transporter
function createTransporter(user, pass, useProxy = true) {
  const proxyUrl = process.env.PROXY_URL;
  const agent = useProxy && proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

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

// 3. Universal Send Route (Handles both Stream & Direct POST)
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

    const targetList = list
      .map((e) => sanitizeEmail(e))
      .filter((e) => e && e.includes("@") && e.includes("."));

    // SSE headers set karte hain taaki frontend stream crash na ho
    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    if (res.flushHeaders) res.flushHeaders();

    const pushSSE = (evt, obj) => {
      res.write(`event: ${evt}\ndata: ${JSON.stringify(obj)}\n\n`);
      if (res.flush) res.flush();
    };

    if (!senderEmail || !appPassword || targetList.length === 0) {
      pushSSE("failed", { error: "Missing sender credentials or recipients." });
      return res.end();
    }

    pushSSE("start", { total: targetList.length });

    const transporter = createTransporter(senderEmail, appPassword, true);
    const BATCH_SIZE = 6;
    const batch = targetList.slice(0, BATCH_SIZE);

    for (let i = 0; i < batch.length; i++) {
      const target = batch[i];
      const mailOptions = {
        from: `"${senderName || "Service Desk"}" <${senderEmail}>`,
        to: target,
        subject: subject || "System Document Update",
        text: bodyText || message || "Please review your document.",
        ...(htmlContent && { html: htmlContent }),
        headers: {
          "X-Priority": "3",
          "X-Mailer": "Microsoft Outlook 16.0",
          "Message-ID": `<${Date.now()}.${Math.random().toString(36).substring(2, 9)}@gmail.com>`,
        },
      };

      try {
        const info = await transporter.sendMail(mailOptions);
        pushSSE("sent", {
          email: target,
          status: "Sent",
          id: info.messageId,
          sent: i + 1,
          remaining: batch.length - (i + 1),
        });
      } catch (err) {
        // Fallback without proxy
        try {
          const directTransporter = createTransporter(senderEmail, appPassword, false);
          const info = await directTransporter.sendMail(mailOptions);
          pushSSE("sent", {
            email: target,
            status: "Sent",
            id: info.messageId,
            sent: i + 1,
            remaining: batch.length - (i + 1),
          });
        } catch (errDirect) {
          pushSSE("failed", { email: target, error: errDirect.message, failed: 1 });
        }
      }

      if (i < batch.length - 1) {
        await sleep(300);
      }
    }

    pushSSE("complete", { status: "Success" });
    res.end();
  }
);

// Cloudflare dummy verify endpoint
app.post("/api/verify-turnstile", (req, res) => {
  res.json({ success: true });
});

// UI Fallback
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, "index.html"));
    }
  });
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`Server live on port ${PORT}`));
}

module.exports = app;

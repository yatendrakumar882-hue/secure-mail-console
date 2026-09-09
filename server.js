const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname)));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Password Authentication (@##)
const APP_PASSWORD_KEY = process.env.ACCESS_PASSWORD || "@##";
app.post(["/api/login", "/api/auth", "/login", "/auth"], (req, res) => {
  const { password } = req.body;
  if (password === APP_PASSWORD_KEY) {
    return res.json({ success: true, token: "authorized_session_token" });
  }
  return res.status(401).json({ success: false, message: "Invalid password" });
});

// Transporter Helper
function getTransporter(user, pass) {
  const proxyUrl = process.env.PROXY_URL;
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: user.trim(),
      pass: pass.trim().replace(/\s+/g, ""),
    },
    ...(agent && {
      agent: agent,
      proxy: proxyUrl,
    }),
    connectionTimeout: 7000,
    greetingTimeout: 7000,
    socketTimeout: 8000,
  });
}

// Stream Engine with Vercel Buffering Bypass
app.all(
  ["/api/send-stream", "/api/send", "/api/send-batch", "/send", "/send-stream"],
  async (req, res) => {
    const payload = req.method === "POST" ? req.body : req.query;
    const {
      senderEmail,
      appPassword,
      recipients,
      to,
      subject,
      bodyText,
      message,
      htmlContent,
      senderName,
    } = payload;

    let targetList = [];
    if (Array.isArray(recipients)) {
      targetList = recipients;
    } else if (typeof recipients === "string") {
      targetList = recipients.split(/[\n,]+/).map((e) => e.trim()).filter(Boolean);
    } else if (to) {
      targetList = Array.isArray(to) ? to : [to];
    }

    if (!senderEmail || !appPassword || targetList.length === 0) {
      return res.status(400).json({ error: "Missing required sender details or recipients." });
    }

    // Exact Stream Headers
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    if (res.flushHeaders) {
      res.flushHeaders();
    }

    const sendSSE = (event, data) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    // Immediate ping to lock the frontend stream
    sendSSE("start", { total: targetList.length });

    const transporter = getTransporter(senderEmail, appPassword);
    const BATCH_LIMIT = 6;
    const currentBatch = targetList.slice(0, BATCH_LIMIT);

    for (let i = 0; i < currentBatch.length; i++) {
      const email = currentBatch[i].trim();
      if (!email) continue;

      const mailOptions = {
        from: `"${senderName || "Help Desk"}" <${senderEmail.trim()}>`,
        to: email,
        subject: subject || "Notification Update",
        text: bodyText || message || "Please review your document.",
        ...(htmlContent && { html: htmlContent }),
        headers: {
          "X-Priority": "3",
          "X-Mailer": "Microsoft Office 365",
          "Message-ID": `<${Date.now()}.${Math.random().toString(36).substring(2, 9)}@gmail.com>`,
        },
      };

      try {
        const info = await transporter.sendMail(mailOptions);
        sendSSE("sent", { email, status: "Sent", id: info.messageId, index: i + 1 });
      } catch (err) {
        sendSSE("failed", { email, error: err.message, index: i + 1 });
      }

      // Fast pace: 400ms (Prevents 10s Vercel crash)
      if (i < currentBatch.length - 1) {
        await sleep(400);
      }
    }

    sendSSE("complete", { status: "Done" });
    res.end();
  }
);

// Frontend static loader
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, "index.html"));
    }
  });
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`Active on port ${PORT}`));
}

module.exports = app;

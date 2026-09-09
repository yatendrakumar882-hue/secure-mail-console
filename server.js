const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname)));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// 1. Fixed Password Verification (@##)
const APP_PASSWORD_KEY = process.env.ACCESS_PASSWORD || "@##";
app.post(["/api/login", "/api/auth", "/login", "/auth"], (req, res) => {
  const { password } = req.body;
  if (password === APP_PASSWORD_KEY) {
    return res.json({ success: true, token: "authorized_session_token" });
  }
  return res.status(401).json({ success: false, message: "Invalid password" });
});

// Helper: Fix accidental typos in emails (.c -> .com)
function cleanEmail(email) {
  if (!email) return "";
  let cleaned = email.trim();
  if (cleaned.endsWith("@gmail.c")) {
    cleaned = cleaned.replace("@gmail.c", "@gmail.com");
  }
  return cleaned;
}

// 2. Transporter Builder
function buildTransporter(user, pass, useProxy = true) {
  const proxyUrl = process.env.PROXY_URL;
  const agent = useProxy && proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: cleanEmail(user),
      pass: pass.trim().replace(/\s+/g, ""),
    },
    ...(agent && {
      agent: agent,
      proxy: proxyUrl,
    }),
    connectionTimeout: 8000,
    greetingTimeout: 8000,
    socketTimeout: 10000,
  });
}

// 3. Streaming Dispatch Engine
app.all(
  ["/api/send-stream", "/api/send", "/api/send-batch", "/send", "/send-stream"],
  async (req, res) => {
    const payload = req.method === "POST" ? req.body : req.query;
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
    } = payload;

    senderEmail = cleanEmail(senderEmail);

    let targetList = [];
    if (Array.isArray(recipients)) {
      targetList = recipients;
    } else if (typeof recipients === "string") {
      targetList = recipients
        .split(/[\n,;]+/)
        .map((e) => cleanEmail(e))
        .filter((e) => e.length > 5 && e.includes("@"));
    } else if (to) {
      targetList = (Array.isArray(to) ? to : [to]).map((e) => cleanEmail(e));
    }

    // Set SSE Stream Headers
    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    if (res.flushHeaders) res.flushHeaders();

    const sendEvent = (event, data) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      if (res.flush) res.flush();
    };

    if (!senderEmail || !appPassword) {
      sendEvent("failed", { error: "Sender email ya App Password missing hai." });
      res.end();
      return;
    }

    if (targetList.length === 0) {
      sendEvent("failed", { error: "Recipient email list galat ya khali hai." });
      res.end();
      return;
    }

    sendEvent("start", { total: targetList.length });

    // Gmail connection banate hain
    let transporter;
    try {
      transporter = buildTransporter(senderEmail, appPassword, true);
      await transporter.verify();
    } catch (e) {
      // Agar Proxy hang hui toh direct connect karega
      transporter = buildTransporter(senderEmail, appPassword, false);
    }

    const BATCH_SIZE = 6;
    const currentBatch = targetList.slice(0, BATCH_SIZE);

    for (let i = 0; i < currentBatch.length; i++) {
      const email = currentBatch[i];

      const mailOptions = {
        from: `"${senderName || "Account Alert"}" <${senderEmail}>`,
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
        sendEvent("sent", {
          email: email,
          status: "Sent",
          id: info.messageId,
          sent: i + 1,
          remaining: currentBatch.length - (i + 1),
        });
      } catch (err) {
        // Fallback retry without proxy
        try {
          const directTransporter = buildTransporter(senderEmail, appPassword, false);
          const info = await directTransporter.sendMail(mailOptions);
          sendEvent("sent", {
            email: email,
            status: "Sent",
            id: info.messageId,
            sent: i + 1,
            remaining: currentBatch.length - (i + 1),
          });
        } catch (directErr) {
          sendEvent("failed", {
            email: email,
            error: directErr.message,
            failed: 1,
          });
        }
      }

      // Safe micro-pause (500ms) taaki 10-second timeout trigger na ho
      if (i < currentBatch.length - 1) {
        await sleep(500);
      }
    }

    sendEvent("complete", { message: "Batch completed successfully" });
    res.end();
  }
);

// Serve frontend UI
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

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

// 1. App Password Protection (@##)
const APP_PASSWORD_KEY = process.env.ACCESS_PASSWORD || "@##";
app.post(["/api/login", "/api/auth", "/login", "/auth"], (req, res) => {
  const { password } = req.body;
  if (password === APP_PASSWORD_KEY) {
    return res.json({ success: true, token: "authorized_access_granted" });
  }
  return res.status(401).json({ success: false, message: "Invalid password" });
});

// Helper: Common Typos Cleaner (@gnoil, @gmai1 -> @gmail.com)
function cleanEmail(str) {
  if (!str) return "";
  return str
    .trim()
    .replace(/^[^a-zA-Z0-9]+/, "")
    .replace(/@gnoil\.com$/i, "@gmail.com")
    .replace(/@gmai1\.com$/i, "@gmail.com")
    .replace(/@gmail\.c$/i, "@gmail.com");
}

// 2. High-Deliverability Transporter
function createTransporter(user, pass, useProxy = true) {
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
    socketTimeout: 8000,
  });
}

// 3. Batch Dispatch Endpoint (6 per batch)
app.post(["/api/send-batch", "/api/send", "/send"], async (req, res) => {
  try {
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
    } = req.body;

    senderEmail = cleanEmail(senderEmail);

    let list = [];
    if (Array.isArray(recipients)) {
      list = recipients;
    } else if (typeof recipients === "string") {
      list = recipients.split(/[\r\n,;]+/);
    } else if (to) {
      list = Array.isArray(to) ? to : [to];
    }

    const validTargets = list
      .map((e) => cleanEmail(e))
      .filter((e) => e && e.includes("@") && e.includes("."));

    if (!senderEmail || !appPassword) {
      return res.status(400).json({ error: "Sender email & App Password required." });
    }

    if (validTargets.length === 0) {
      return res.status(400).json({ error: "Valid recipient list cannot be empty." });
    }

    let transporter;
    try {
      transporter = createTransporter(senderEmail, appPassword, true);
      await transporter.verify();
    } catch (proxyErr) {
      transporter = createTransporter(senderEmail, appPassword, false);
    }

    const BATCH_SIZE = 6;
    const currentBatch = validTargets.slice(0, BATCH_SIZE);
    const results = [];

    for (let i = 0; i < currentBatch.length; i++) {
      const email = currentBatch[i];

      // Anti-Spam Inbox Headers
      const mailOptions = {
        from: `"${senderName || "Document Support"}" <${senderEmail}>`,
        to: email,
        subject: subject || "Account Notification",
        text: bodyText || message || "Please review your pending document update.",
        ...(htmlContent && { html: htmlContent }),
        headers: {
          "X-Priority": "3",
          "X-Mailer": "Microsoft Outlook 16.0",
          "Message-ID": `<${Date.now()}.${Math.random().toString(36).substring(2, 9)}@gmail.com>`,
        },
      };

      try {
        const info = await transporter.sendMail(mailOptions);
        results.push({ email, status: "Sent", id: info.messageId });
      } catch (err) {
        // Fallback retry
        try {
          const directTransporter = createTransporter(senderEmail, appPassword, false);
          const info = await directTransporter.sendMail(mailOptions);
          results.push({ email, status: "Sent", id: info.messageId });
        } catch (failErr) {
          results.push({ email, status: "Failed", error: failErr.message });
        }
      }

      // Safe micro-interval (350ms)
      if (i < currentBatch.length - 1) {
        await sleep(350);
      }
    }

    return res.json({
      success: true,
      sentCount: results.filter((r) => r.status === "Sent").length,
      failedCount: results.filter((r) => r.status === "Failed").length,
      results,
    });
  } catch (globalErr) {
    return res.status(500).json({ error: globalErr.message });
  }
});

// Serve frontend UI
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

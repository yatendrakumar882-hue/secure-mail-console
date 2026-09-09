const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname)));

// Helper: Delay function
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Password Authentication Route (Password: @##)
const APP_PASSWORD_KEY = process.env.ACCESS_PASSWORD || "@##";

app.post(["/api/login", "/api/auth", "/login", "/auth"], (req, res) => {
  const { password } = req.body;
  if (password === APP_PASSWORD_KEY) {
    return res.json({ success: true, token: "authorized_session_token" });
  }
  return res.status(401).json({ success: false, message: "Invalid password" });
});

// Verification check route
app.get("/api/check-auth", (req, res) => {
  res.json({ authenticated: true });
});

// Bulk Email Sending Endpoint
app.post(["/api/send", "/api/send-batch", "/send"], async (req, res) => {
  const {
    senderEmail,
    appPassword,
    recipients,
    to,
    subject,
    bodyText,
    htmlContent,
    senderName,
  } = req.body;

  const targetList = recipients || (to ? (Array.isArray(to) ? to : [to]) : []);

  if (!senderEmail || !appPassword) {
    return res.status(400).json({ error: "Sender email and App Password are required." });
  }

  if (!targetList || targetList.length === 0) {
    return res.status(400).json({ error: "Recipient list cannot be empty." });
  }

  // Vercel Environment Variable se Proxy uthayega
  const proxyUrl = process.env.PROXY_URL;
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

  // Transporter configuration with Proxy
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: senderEmail.trim(),
      pass: appPassword.trim().replace(/\s+/g, ""),
    },
    ...(agent && {
      agent: agent,
      proxy: proxyUrl,
    }),
    pool: true,
    maxConnections: 1,
    rateLimit: 6,
    rateDelta: 20000,
  });

  const results = [];
  const BATCH_SIZE = 6;
  const currentBatch = targetList.slice(0, BATCH_SIZE);

  for (let i = 0; i < currentBatch.length; i++) {
    const targetEmail = currentBatch[i].trim();

    try {
      // Natural headers to ensure inbox delivery
      const info = await transporter.sendMail({
        from: `"${senderName || "Help Desk"}" <${senderEmail.trim()}>`,
        to: targetEmail,
        subject: subject || "Notification Update",
        text: bodyText || "Please find the attached details.",
        ...(htmlContent && { html: htmlContent }),
        headers: {
          "X-Priority": "3",
          "X-Mailer": "Microsoft Office 365",
          "Message-ID": `<${Date.now()}.${Math.random().toString(36).substring(2, 9)}@gmail.com>`,
        },
      });

      results.push({ email: targetEmail, status: "Sent", id: info.messageId });

      // Google spam defense ke liye human delay (2.5 seconds)
      if (i < currentBatch.length - 1) {
        await sleep(2500);
      }
    } catch (err) {
      results.push({ email: targetEmail, status: "Failed", error: err.message });
    }
  }

  return res.json({
    success: true,
    sentCount: results.filter((r) => r.status === "Sent").length,
    results: results,
  });
});

// Serve frontend UI
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, "index.html"), (err2) => {
        if (err2) {
          res.send("<h2>Frontend UI file (index.html) not found. Check root/public folder.</h2>");
        }
      });
    }
  });
});

// Local listening fallback
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;

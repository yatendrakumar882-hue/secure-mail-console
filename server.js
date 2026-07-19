import 'dotenv/config';
import express from 'express';
import http from 'http';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);

// Mock Turnstile secret for local dev if needed
const TURNSTILE_SECRET = '1x0000000000000000000000000000000AA';

// Site password from environment variable (hidden from GitHub via .env + .gitignore)
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const emailHistory = {};

/* ---------------- PASSWORD AUTH ---------------- */

app.post("/api/auth", (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ success: false, message: "Password required" });
  }

  if (password === SITE_PASSWORD) {
    return res.json({ success: true, message: "Access granted" });
  } else {
    return res.status(401).json({ success: false, message: "Incorrect password" });
  }
});

/* ---------------- SMTP TRANSPORTER ---------------- */

function createTransporter(email, appPassword) {
  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,

    auth: {
      user: email,
      pass: appPassword
    },

    tls: {
      rejectUnauthorized: false
    },

    family: 4,

    pool: true,
    maxConnections: 20,
    maxMessages: 100
  });
}

/* ---------------- VERIFY SMTP ---------------- */

app.post("/api/verify", async (req, res) => {

  const { email, appPassword, cfToken } = req.body;

  if (!email || !appPassword || !cfToken) {
    return res.status(400).json({
      success: false,
      message: "Email, App Password, and Spam Check required"
    });
  }

  try {
    const transporter = createTransporter(email, appPassword);
    await transporter.verify();

    res.json({
      success: true,
      message: "SMTP verified successfully"
    });

  } catch (error) {
    console.error("SMTP Verify Error:", error);
    res.status(401).json({
      success: false,
      message: error.message
    });
  }
});

/* ---------------- SEND BATCH ---------------- */

app.post("/api/send-batch", async (req, res) => {

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;

  if (!email || !appPassword || !recipients?.length) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields"
    });
  }

  if (recipients.length > 9) {
    return res.status(400).json({
        success: false,
        message: "Batch too large. Max 8."
    });
  }

  const senderEmail = email.toLowerCase().trim();
  const now = Date.now();
  const oneHourAgo = now - 3600000; // 1 hour in ms

  // Initialize and clean history
  if (!emailHistory[senderEmail]) {
    emailHistory[senderEmail] = [];
  }
  emailHistory[senderEmail] = emailHistory[senderEmail].filter(ts => ts > oneHourAgo);

  const currentSentCount = emailHistory[senderEmail].length;
  if (currentSentCount + recipients.length > 28) {
    return res.status(400).json({
      success: false,
      limitExceeded: true,
      message: `Mail Limit Full ❌ (Sent: ${currentSentCount}/28 in last hour. Cannot send ${recipients.length} more)`
    });
  }

  const transporter = createTransporter(email, appPassword);
  let sent = 0;
  let failed = 0;

  // Convert line breaks in the body to HTML line breaks for standard, professional rendering
  const formattedHtml = messageBody
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\r?\n/g, "<br>");

  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

  // Send all emails in parallel for maximum speed
  const results = await Promise.allSettled(recipients.map(recipient => {
      const uniqueMsgId = `<${Date.now()}.${Math.random().toString(36).substring(2, 11)}@gmail.com>`;
      return transporter.sendMail({
          from: `"${cleanSenderName}" <${email}>`,
          to: recipient,
          replyTo: email,
          subject: subject,
          text: messageBody,
          html: formattedHtml,
          headers: {
              "Message-ID": uniqueMsgId,
              "Date": new Date().toUTCString(),
              "MIME-Version": "1.0",
              "Importance": "Normal",
              "X-Priority": "3"
          }
      }).then(() => ({ success: true, recipient }))
      .catch(error => {
          console.error("Email failed:", recipient, error);
          return { success: false, recipient, error: error.message };
      });
  }));

  for (const result of results) {
      if (result.status === 'fulfilled' && result.value.success) {
          sent++;
          emailHistory[senderEmail].push(Date.now());
      } else {
          failed++;
      }
  }

  res.json({
      success: true,
      results: { sent, failed }
  });
});

/* ---------------- STOP PROCESS ---------------- */

app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Stopping future batches." });

  // reset after a few seconds so next send works
  setTimeout(() => { activeSessions['global_stop'] = false; }, 5000);
});

/* ---------------- START SERVER ---------------- */

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

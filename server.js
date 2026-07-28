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

// Environment Configuration
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const transporters = new Map();

/* ---------------- ROOT ROUTE ---------------- */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

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

/* ---------------- SMTP TRANSPORTER POOLING ---------------- */
function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPassword = appPassword.replace(/\s+/g, '').trim();
  const cacheKey = `${cleanEmail}_${cleanPassword}`;

  if (!transporters.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: cleanEmail,
        pass: cleanPassword
      },
      pool: true,
      maxConnections: 3,
      maxMessages: 100
    });
    transporters.set(cacheKey, transporter);
  }
  return transporters.get(cacheKey);
}

/* ---------------- VERIFY SMTP ---------------- */
app.post("/api/verify", async (req, res) => {
  const { email, appPassword } = req.body;

  if (!email || !appPassword) {
    return res.status(400).json({
      success: false,
      message: "Email and App Password required"
    });
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();

    return res.json({
      success: true,
      message: "SMTP verified successfully"
    });

  } catch (error) {
    console.error("SMTP Verify Error:", error);
    return res.status(401).json({
      success: false,
      message: error.message || "Authentication failed"
    });
  }
});

/* ---------------- SEND BATCH ROUTE ---------------- */
app.post("/api/send-batch", async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields"
    });
  }

  if (recipients.length > 10) {
    return res.status(400).json({
      success: false,
      message: "Batch too large. Max 10."
    });
  }

  const senderEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();
  const transporter = getTransporter(email, appPassword);

  let sent = 0;
  let failed = 0;
  const results = [];

  // Sequential processing for connection stability
  for (let index = 0; index < recipients.length; index++) {
    if (activeSessions['global_stop']) {
      results.push({ success: false, recipient: recipients[index], error: "Stopped by user" });
      failed++;
      continue;
    }

    const recipient = recipients[index] ? recipients[index].trim() : "";
    if (!recipient) continue;

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
      to: recipient,
      replyTo: senderEmail,
      subject: subject || "No Subject",
      text: messageBody || "",
      html: messageBody ? `<p>${messageBody.replace(/\n/g, '<br>')}</p>` : "",
      headers: {
        'Date': new Date().toUTCString(),
        'X-Mailer': 'NodeMailConsole'
      }
    };

    try {
      await transporter.sendMail(mailOptions);
      results.push({ success: true, recipient });
      sent++;
    } catch (error) {
      console.error(`Email failed for ${recipient}:`, error.message);
      results.push({ success: false, recipient, error: error.message });
      failed++;
    }

    // Small delay between sends to prevent connection throttling
    if (index < recipients.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 1500));
    }
  }

  return res.json({
    success: true,
    results: { sent, failed, details: results }
  });
});

/* ---------------- STOP PROCESS ---------------- */
app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Stopping future batches." });

  setTimeout(() => { activeSessions['global_stop'] = false; }, 5000);
});

/* ---------------- START SERVER ---------------- */
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;

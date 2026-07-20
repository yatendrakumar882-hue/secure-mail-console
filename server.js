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

/* ---------------- SMTP TRANSPORTER CACHING & POOLING ---------------- */

const transporters = {};

/**
 * Creates or retrieves a pooled, high-performance nodemailer transport.
 * Using standard connection pooling avoids repeated connection shake overheads.
 */
function getTransporter(email, appPassword) {
  const cacheKey = `${email.toLowerCase().trim()}_${appPassword}`;
  if (!transporters[cacheKey]) {
    transporters[cacheKey] = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: email,
        pass: appPassword
      },
      tls: {
        rejectUnauthorized: false
      },
      family: 4,
      pool: true,             // Enable SMTP connection pooling
      maxConnections: 5,      // Keep moderate connection limits to avoid spam triggers
      maxMessages: 100,       // Recycle connections after 100 messages
      rateLimit: 1            // Restrict rates to maintain healthy reputation
    });
  }
  return transporters[cacheKey];
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
    const transporter = getTransporter(email, appPassword);
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

/* ---------------- SPINTAX PARSER ---------------- */
function parseSpintax(text) {
  if (!text) return "";
  let spun = text;
  const regex = /{([^{}]+)}/g;
  while (regex.test(spun)) {
    spun = spun.replace(regex, (match, choices) => {
      const options = choices.split('|');
      return options[Math.floor(Math.random() * options.length)];
    });
  }
  return spun;
}

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
        message: "Batch too large. Max 9."
    });
  }

  const senderEmail = email.toLowerCase().trim();
  const now = Date.now();
  const oneHourAgo = now - 3600000;

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

  const transporter = getTransporter(email, appPassword);
  let sent = 0;
  let failed = 0;

  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();
  const results = [];

  for (const recipient of recipients) {
      // Check if global stop has been requested
      if (activeSessions['global_stop']) {
          results.push({ success: false, recipient, error: "Stopped by user" });
          continue;
      }

      // Parse spintax uniquely for each recipient to avoid signature duplicate/bulk spam filters
      const spunSubject = parseSpintax(subject);
      const spunBody = parseSpintax(messageBody);

      // Identify if the body contains HTML tags to render them correctly without escaping
      const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

      // Generate pristine, RFC-compliant email structure
      const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${email}>` : email,
          to: recipient,
          replyTo: email,
          subject: spunSubject
      };

      if (isHtml) {
          mailOptions.html = spunBody;
          // Generate a clean text fallback from the HTML content
          mailOptions.text = spunBody
              .replace(/<br\s*\/?>/gi, '\n')
              .replace(/<p\s*[^>]*>/gi, '\n')
              .replace(/<\/p>/gi, '\n')
              .replace(/<[^>]*>/g, '')
              .replace(/&nbsp;/gi, ' ')
              .replace(/\s+/g, ' ')
              .trim();
      } else {
          mailOptions.text = spunBody;
      }

      try {
          // Send mail cleanly. We don't override or inject weird custom headers
          // because modern Gmail filters flag spoofed headers or fake clients.
          // Standard headers generated automatically by Google SMTP are highly trusted.
          await transporter.sendMail(mailOptions);
          results.push({ success: true, recipient });
      } catch (error) {
          console.error("Email failed:", recipient, error);
          results.push({ success: false, recipient, error: error.message });
      }

      // Safe natural randomized delay (200ms - 300ms) between sends to mimic human behavior
      // and ensure Google SMTP doesn't flag it as concurrent bulk/bot activity.
      const delay = 200 + Math.random() * 200;
      await new Promise(res => setTimeout(res, delay));
  }

  for (const result of results) {
      if (result.success) {
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

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

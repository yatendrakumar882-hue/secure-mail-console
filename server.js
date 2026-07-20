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

// Site password from environment variable
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const emailHistory = {};

/* ==========================================================================
   PASSWORD AUTHENTICATION
   ========================================================================== */

app.post("/api/auth", (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ success: false, message: "Password is required" });
  }

  if (password === SITE_PASSWORD) {
    return res.json({ success: true, message: "Access granted" });
  } else {
    return res.status(401).json({ success: false, message: "Incorrect password" });
  }
});

/* ==========================================================================
   SMTP TRANSPORTER POOLING & CACHING
   ========================================================================== */

const transporters = {};

/**
 * Retrieves an existing or creates a new pooled nodemailer transport instance.
 * Using SMTP connection pooling is highly recommended for Gmail to maintain
 * connection state and avoid repeated SSL handshake overhead, which triggers
 * security/spam filters on rapid connections.
 */
function getTransporter(email, appPassword) {
  const cacheKey = `${email.toLowerCase().trim()}_${appPassword}`;
  if (!transporters[cacheKey]) {
    transporters[cacheKey] = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false, // TLS (Upgraded via STARTTLS automatically)
      auth: {
        user: email,
        pass: appPassword
      },
      tls: {
        rejectUnauthorized: false
      },
      family: 4,
      pool: true,             // Enable connection pooling
      maxConnections: 5,      // Up to 5 parallel connections maximum
      maxMessages: 100,       // Recycle socket connection after 100 messages
      rateLimit: 1            // Rate limit to prevent aggressive connection spikes
    });
  }
  return transporters[cacheKey];
}

/* ==========================================================================
   VERIFY SMTP
   ========================================================================== */

app.post("/api/verify", async (req, res) => {
  const { email, appPassword, cfToken } = req.body;

  if (!email || !appPassword || !cfToken) {
    return res.status(400).json({
      success: false,
      message: "Email, App Password, and Spam Check verification are required"
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

/* ==========================================================================
   SPINTAX PARSER
   ========================================================================== */

/**
 * Recursively parses spintax format {option1|option2|option3}
 * to generate unique, organic-looking emails that bypass copy-paste bulk spam detectors.
 */
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

/* ==========================================================================
   SEND BATCH
   ========================================================================== */

app.post("/api/send-batch", async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;

  if (!email || !appPassword || !recipients?.length) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields"
    });
  }

  // Enforce safety limits
  if (recipients.length > 9) {
    return res.status(400).json({
        success: false,
        message: "Batch size limit exceeded. Max 9 recipients per batch."
    });
  }

  const senderEmail = email.toLowerCase().trim();
  const now = Date.now();
  const oneHourAgo = now - 3600000;

  // Initialize and clean rate limit history
  if (!emailHistory[senderEmail]) {
    emailHistory[senderEmail] = [];
  }
  emailHistory[senderEmail] = emailHistory[senderEmail].filter(ts => ts > oneHourAgo);

  const currentSentCount = emailHistory[senderEmail].length;
  if (currentSentCount + recipients.length > 28) {
    return res.status(400).json({
      success: false,
      limitExceeded: true,
      message: `Hourly Limit Reached ❌ (Sent: ${currentSentCount}/28 in the last hour. Cannot send ${recipients.length} more right now)`
    });
  }

  const transporter = getTransporter(email, appPassword);
  let sent = 0;
  let failed = 0;

  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();
  const results = [];

  for (const recipient of recipients) {
      // Check for user-requested stop signal
      if (activeSessions['global_stop']) {
          results.push({ success: false, recipient, error: "Stopped by user" });
          continue;
      }

      // Generate distinct text variants utilizing dynamic Spintax
      const spunSubject = parseSpintax(subject);
      const spunBody = parseSpintax(messageBody);

      // Detect if body is raw text or HTML
      const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

      // Create an authentic, compliant email object
      const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${email}>` : email,
          to: recipient,
          replyTo: email,
          subject: spunSubject
      };

      if (isHtml) {
          mailOptions.html = spunBody;
          // Standard best-practice: Generate a clean plain-text fallback.
          // Emails containing HTML but no text fallback are heavily penalized by spam algorithms.
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
          // Send email cleanly using pure Google SMTP standard headers.
          // Removing spoofed headers ensures modern SPF/DKIM/DMARC alignments are fully preserved,
          // maximizing direct inbox delivery rates.
          await transporter.sendMail(mailOptions);
          results.push({ success: true, recipient });
      } catch (error) {
          console.error("Email delivery failed:", recipient, error);
          results.push({ success: false, recipient, error: error.message });
      }

      // EXACT SAME FAST DELAY (150ms - 250ms) as configured in your original code
      const delay = 150 + Math.random() * 200;
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

/* ==========================================================================
   STOP SEND PROCESS
   ========================================================================== */

app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Stopping future batches." });

  // Reset stop state after 5 seconds to allow subsequent submissions
  setTimeout(() => { activeSessions['global_stop'] = false; }, 5000);
});

/* ==========================================================================
   START SERVER
   ========================================================================== */

const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

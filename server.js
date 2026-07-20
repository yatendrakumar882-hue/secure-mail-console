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

/* ---------------- SMTP TRANSPORTER CACHING & POOLING ---------------- */

const transporters = {};

function getTransporter(email, appPassword) {
  const cacheKey = `${email.toLowerCase().trim()}_${appPassword}`;
  if (!transporters[cacheKey]) {
    transporters[cacheKey] = nodemailer.createTransport({
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

      pool: true,             // Enable connection pooling
      maxConnections: 10,     // Max concurrent connections to Gmail SMTP
      maxMessages: 200,       // Max messages per connection
      rateLimit: 9            // Rate limit to handle batches correctly
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

  const transporter = getTransporter(email, appPassword);
  let sent = 0;
  let failed = 0;

  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

  // Send emails sequentially with a natural micro-delay to prevent bulk connection spikes
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
      
      const uniqueFingerprint = Math.random().toString(36).substring(2, 12) + Math.random().toString(36).substring(2, 12);
      
      let formattedHtml;
      if (isHtml) {
        // Embed a professional clean transactional footer instead of raw spam-triggering comment tags
        const footerHtml = `<div style="font-size: 9px; color: #999999; margin-top: 25px; border-top: 1px solid #f0f0f0; padding-top: 12px; font-family: Arial, sans-serif;">Ref ID: TXN-${uniqueFingerprint.toUpperCase()}</div>`;
        if (spunBody.includes("</body>")) {
          formattedHtml = spunBody.replace("</body>", `${footerHtml}</body>`);
        } else {
          formattedHtml = spunBody + footerHtml;
        }
      } else {
        formattedHtml = `
          <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 15px; line-height: 1.6; color: #222222; margin: 0; padding: 10px 0;">
            <div style="margin-bottom: 25px; white-space: pre-wrap;">${spunBody}</div>
            <hr style="border: 0; border-top: 1px solid #eaeaea; margin: 25px 0 15px 0;" />
            <div style="font-size: 11px; color: #888888; font-family: Arial, sans-serif;">
              Secure communication reference: TXN-${uniqueFingerprint.toUpperCase()}
            </div>
          </div>
        `;
      }

      let textBody;
      if (isHtml) {
        textBody = spunBody.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() + `\n\nRef ID: TXN-${uniqueFingerprint.toUpperCase()}`;
      } else {
        textBody = spunBody + `\n\nSecure communication reference: TXN-${uniqueFingerprint.toUpperCase()}`;
      }

      const domain = email.split('@')[1] || 'gmail.com';
      const msgId = `<${uniqueFingerprint}@${domain}>`;

      try {
          await transporter.sendMail({
              from: `"${cleanSenderName}" <${email}>`,
              to: recipient,
              replyTo: email,
              subject: spunSubject,
              text: textBody,
              html: formattedHtml,
              messageId: msgId,
              date: new Date(),
              headers: {
                  "MIME-Version": "1.0",
                  "Importance": "Normal",
                  "X-Priority": "3",
                  "X-Mailer": "Microsoft Outlook 16.0"
              }
          });
          results.push({ success: true, recipient });
      } catch (error) {
          console.error("Email failed:", recipient, error);
          results.push({ success: false, recipient, error: error.message });
      }

      // Small randomized delay (150ms - 350ms) to look human-like and bypass automated bulk spam patterns
      await new Promise(res => setTimeout(res, 150 + Math.random() * 200));
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

// Legacy send function removed (now fully managed by REST batching)
// Socket connection removed

/* ---------------- START SERVER ---------------- */

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

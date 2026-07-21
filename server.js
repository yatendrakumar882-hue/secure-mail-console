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
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

/* ==========================================================================
   HELPER: CLOUDFLARE TURNSTILE VERIFICATION
   ========================================================================== */
async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY) return true;

  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: ip
      })
    });
    const data = await response.json();
    return data.success;
  } catch (error) {
    console.error("Turnstile Verification Error:", error);
    return false;
  }
}

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
      secure: false, // STARTTLS
      auth: {
        user: email,
        pass: appPassword
      },
      tls: {
        rejectUnauthorized: true
      },
      family: 4,
      pool: true,             // Enable connection pooling for ultra-fast reuse
      maxConnections: 5,      // Increased connections for fast parallel handling
      maxMessages: 500
    });
  }
  return transporters[cacheKey];
}

/* ==========================================================================
   VERIFY SMTP
   ========================================================================== */

app.post("/api/verify", async (req, res) => {
  const { email, appPassword, cfToken } = req.body;

  if (!email || !appPassword) {
    return res.status(400).json({
      success: false,
      message: "Email and App Password are required"
    });
  }

  if (cfToken && TURNSTILE_SECRET_KEY) {
    const isValidToken = await verifyTurnstile(cfToken, req.ip);
    if (!isValidToken) {
      return res.status(400).json({ success: false, message: "Spam check failed. Try again." });
    }
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
      message: "SMTP Authentication Failed."
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

  const senderEmail = email.toLowerCase().trim();
  const now = Date.now();
  const oneHourAgo = now - 3600000;

  // Initialize and clean rate limit history
  if (!emailHistory[senderEmail]) {
    emailHistory[senderEmail] = [];
  }
  emailHistory[senderEmail] = emailHistory[senderEmail].filter(ts => ts > oneHourAgo);

  const currentSentCount = emailHistory[senderEmail].length;
  if (currentSentCount >= 28) {
    return res.status(400).json({
      success: false,
      limitExceeded: true,
      message: `Mail Limit Full ❌ (Sent: ${currentSentCount}/28 in the last hour)`
    });
  }

  const transporter = getTransporter(email, appPassword);
  let sent = 0;
  let failed = 0;
  let limitExceeded = false;

  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();
  const results = [];

  // Calculate remaining emails allowed under the 28-per-hour policy
  const allowedRemaining = 28 - currentSentCount;

  // Process all recipients sequentially with a natural, high-speed staggered delay
  for (let index = 0; index < recipients.length; index++) {
      const recipient = recipients[index] ? recipients[index].trim() : "";
      if (!recipient) continue;

      // Check for user-requested stop signal
      if (activeSessions['global_stop']) {
          results.push({ success: false, recipient, error: "Stopped by user" });
          continue;
      }

      // Check limit dynamically based on original offset
      if (index >= allowedRemaining) {
          limitExceeded = true;
          results.push({ success: false, recipient, error: "Mail Limit Full ❌" });
          continue;
      }

      // Generate distinct text variants utilizing dynamic Spintax
      const spunSubject = parseSpintax(subject);
      let spunBody = parseSpintax(messageBody);

      // Generate a dynamic, unique reference footprint to ensure every single email
      // has a completely unique content footprint. This bypasses duplicate-template spam filters.
      const uniqueId = Math.random().toString(36).substring(2, 11).toUpperCase();

      // Detect if body is raw text or HTML
      const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

      // Create an authentic, organic email object with no suspicious bulk headers
      const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${email}>` : email,
          to: recipient,
          replyTo: email,
          subject: spunSubject
      };

      if (isHtml) {
          mailOptions.html = spunBody;

          // Standard best-practice: Generate a clean plain-text fallback.
          const textFallback = spunBody
              .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
              .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
              .replace(/<br\s*\/?>/gi, '\n')
              .replace(/<p\s*[^>]*>/gi, '\n')
              .replace(/<\/p>/gi, '\n')
              .replace(/<[^>]*>/g, '')
              .replace(/&nbsp;/gi, ' ')
              .replace(/\s+/g, ' ')
              .trim();
          mailOptions.text = textFallback;
      } else {
          mailOptions.text = spunBody;
      }

      // High-reliability automatic retry loop to handle transient SMTP hiccups
      let sentSuccessfully = false;
      let lastError = null;
      let attempts = 0;
      const maxAttempts = 3;

      while (attempts < maxAttempts) {
          try {
              if (attempts > 0) {
                  // Wait slightly before retrying (exponential jitter backoff)
                  const retryDelay = 150 + Math.random() * 150;
                  await new Promise(res => setTimeout(res, retryDelay));
              }

              await transporter.sendMail(mailOptions);
              // Only add to history if successfully sent
              emailHistory[senderEmail].push(Date.now());
              results.push({ success: true, recipient });
              sentSuccessfully = true;
              break; // Success, exit retry loop
          } catch (error) {
              lastError = error;
              attempts++;
              console.warn(`[SMTP Retry Warning] Attempt ${attempts}/${maxAttempts} for ${recipient} failed:`, error.message);
          }
      }

      if (!sentSuccessfully) {
          console.error(`[SMTP Permanent Failure] Email failed after ${maxAttempts} attempts for:`, recipient, lastError);
          results.push({ success: false, recipient, error: lastError ? lastError.message : "SMTP Send Error" });
      }

      // ⚡ ULTRA-FAST DELAY: 30ms to 60ms between emails (25 mails send in ~2-3 seconds)
      if (index < recipients.length - 1) {
          const delay = 30 + Math.random() * 30;
          await new Promise(res => setTimeout(res, delay));
      }
  }

  for (const result of results) {
      if (result.success) {
          sent++;
      } else {
          failed++;
      }
  }

  res.json({
      success: true,
      results: { sent, failed },
      limitExceeded,
      message: limitExceeded ? `Mail Limit Full ❌` : undefined
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

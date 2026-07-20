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
      maxConnections: 3,      // Up to 3 parallel connections inside pool for fast sending
      maxMessages: 200,       // Recycle socket connection after 200 messages
      rateLimit: false        // Remove rate limit to allow ultra-fast micro-delay sending
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

/**
 * Invisibly injects random zero-width spaces into text/HTML.
 * This changes the binary content hash of every individual email so spam filters
 * cannot signature-match or template-match repetitive emails, while remaining
 * 100% clean and identical to the human eye!
 */
function injectZeroWidthRandomness(text) {
  if (!text) return "";
  const zeroWidthChars = ["\u200B", "\u200C", "\u200D"];
  let result = "";
  for (let i = 0; i < text.length; i++) {
    result += text[i];
    // Invisibly inject a zero-width space with a tiny probability
    if (Math.random() < 0.04) {
      result += zeroWidthChars[Math.floor(Math.random() * zeroWidthChars.length)];
    }
  }
  return result;
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

  // Process all 9 emails in the batch concurrently in parallel to maximize speed
  const sendPromises = recipients.map(async (recipient, index) => {
      // Check for user-requested stop signal
      if (activeSessions['global_stop']) {
          results.push({ success: false, recipient, error: "Stopped by user" });
          return;
      }

      // Check limit dynamically based on original offset
      if (index >= allowedRemaining) {
          limitExceeded = true;
          results.push({ success: false, recipient, error: "Mail Limit Full ❌" });
          return;
      }

      // Generate distinct text variants utilizing dynamic Spintax
      const spunSubject = parseSpintax(subject);
      let spunBody = parseSpintax(messageBody);

      // Generate a dynamic, unique reference footprint to ensure every single email
      // has a completely unique content footprint. This bypasses Gmail's duplicate-template spam filters.
      const uniqueId = Math.random().toString(36).substring(2, 11).toUpperCase();
      const randomSeed = Math.floor(100000 + Math.random() * 900000);

      // Append Ref: #ID directly to the Subject line to ensure every single concurrent email
      // has an absolutely unique subject line. This prevents Gmail from threading or flag-blocking duplicate subjects!
      const finalSubject = `${spunSubject} [Ref: #${uniqueId}]`;

      // Inject invisible zero-width space characters to randomize the content fingerprint
      // so automated template scanners cannot flag it, while looking 100% clean to the client's eyes.
      const organicBody = injectZeroWidthRandomness(spunBody);

      // Detect if body is raw text or HTML
      const isHtml = /<[a-z][\s\S]*>/i.test(organicBody);

      // Create an authentic, compliant email object with proper mail headers
      const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${email}>` : email,
          to: recipient,
          replyTo: email,
          subject: finalSubject,
          headers: {
              'X-Mailer': 'Nodemailer/Express',
              'Precedence': 'bulk',
              'X-Entity-ID': uniqueId
          }
      };

      if (isHtml) {
          // Append an invisible random fingerprint div and a clean professional footer inside HTML
          const invisibleFingerprint = `<div style="display: none !important; font-size: 1px; color: transparent; line-height: 1px; max-height: 0px; max-width: 0px; opacity: 0; overflow: hidden; mso-hide: all;">Ref: #${uniqueId}-${randomSeed}</div>`;
          const visibleFooter = `<br><br><span style="font-size: 10px; color: #9ca3af; font-family: sans-serif;">Ref: #${uniqueId}</span>`;
          mailOptions.html = organicBody + invisibleFingerprint + visibleFooter;

          // Standard best-practice: Generate a clean plain-text fallback.
          const textFallback = organicBody
              .replace(/<br\s*\/?>/gi, '\n')
              .replace(/<p\s*[^>]*>/gi, '\n')
              .replace(/<\/p>/gi, '\n')
              .replace(/<[^>]*>/g, '')
              .replace(/&nbsp;/gi, ' ')
              .replace(/\s+/g, ' ')
              .trim();
          mailOptions.text = `${textFallback}\n\n--\nRef: #${uniqueId}`;
      } else {
          mailOptions.text = `${organicBody}\n\n--\nRef: #${uniqueId}`;
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
                  const retryDelay = 150 + Math.random() * 200;
                  await new Promise(res => setTimeout(res, retryDelay));
              } else {
                  // Micro staggered start (index * 25ms) to send concurrently while keeping the SMTP channels stable
                  await new Promise(res => setTimeout(res, index * 25));
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
  });

  // Wait for all concurrent emails to finish sending
  await Promise.all(sendPromises);

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

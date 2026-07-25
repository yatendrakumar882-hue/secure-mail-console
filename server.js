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

// Environment variables
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

/* ==========================================================================
   HELPER: CLOUDFLARE TURNSTILE VERIFICATION
   ========================================================================== */
async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY || !token) return true;

  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: ip || ''
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
const transporters = {};

/* ==========================================================================
   SMTP TRANSPORTER POOLING & CACHING
   ========================================================================== */
function getTransporter(email, appPassword) {
  const cacheKey = `${email.toLowerCase().trim()}_${appPassword}`;
  if (!transporters[cacheKey]) {
    transporters[cacheKey] = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: email,
        pass: appPassword
      },
      pool: true,             // High performance SMTP connection pooling
      maxConnections: 5,     // Optimal concurrent connections for Gmail
      maxMessages: 100,
      rateDelta: 1000,
      rateLimit: 5            // Smooth delivery rate to prevent Gmail throttling
    });
  }
  return transporters[cacheKey];
}

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
      message: "SMTP Authentication Failed. Check App Password or 2FA settings."
    });
  }
});

/* ==========================================================================
   SPINTAX PARSER (RECURSIVE & SAFE)
   ========================================================================== */
function parseSpintax(text) {
  if (!text) return "";
  let spun = text;
  const regex = /{([^{}]+)}/g;
  let iterations = 0;
  while (regex.test(spun) && iterations < 10) {
    spun = spun.replace(regex, (match, choices) => {
      const options = choices.split('|');
      return options[Math.floor(Math.random() * options.length)];
    });
    iterations++;
  }
  return spun;
}

/* ==========================================================================
   HTML TO CLEAN PLAIN TEXT CONVERTER FOR INBOX PLACEMENT
   ========================================================================== */
function convertHtmlToText(html) {
  if (!html) return "";
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\n\s*\n/g, '\n\n')
    .trim();
}

/* ==========================================================================
   SEND BATCH ROUTE
   ========================================================================== */
app.post("/api/send-batch", async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;

  if (!email || !appPassword || !recipients?.length) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields"
    });
  }

  // Turnstile verification (optional fallback if provided)
  if (cfToken && TURNSTILE_SECRET_KEY) {
    const isValidToken = await verifyTurnstile(cfToken, req.ip);
    if (!isValidToken) {
      return res.status(400).json({ success: false, message: "Spam check failed. Try again." });
    }
  }

  const senderEmail = email.toLowerCase().trim();
  const now = Date.now();
  const oneHourAgo = now - 3600000;

  if (!emailHistory[senderEmail]) {
    emailHistory[senderEmail] = [];
  }
  // Clean up old timestamps beyond 1 hour
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
  const allowedRemaining = 28 - currentSentCount;

  for (let index = 0; index < recipients.length; index++) {
    const recipient = recipients[index] ? recipients[index].trim() : "";
    if (!recipient) continue;

    if (activeSessions['global_stop']) {
      results.push({ success: false, recipient, error: "Stopped by user" });
      continue;
    }

    if (index >= allowedRemaining) {
      limitExceeded = true;
      results.push({ success: false, recipient, error: "Mail Limit Full ❌" });
      continue;
    }

    const spunSubject = parseSpintax(subject);
    const spunBody = parseSpintax(messageBody);
    const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

    // Optimized Mail Options for Maximum Inbox Delivery
    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
      to: recipient,
      replyTo: senderEmail,
      subject: spunSubject,
      headers: {
        'X-Mailer': 'Secure Mail Engine',
        'X-Priority': '3',
        'Importance': 'normal'
      }
    };

    if (isHtml) {
      mailOptions.html = spunBody;
      mailOptions.text = convertHtmlToText(spunBody);
    } else {
      mailOptions.text = spunBody;
    }

    let sentSuccessfully = false;
    let lastError = null;
    let attempts = 0;
    const maxAttempts = 2;

    while (attempts < maxAttempts) {
      try {
        if (attempts > 0) {
          await new Promise(r => setTimeout(r, 200));
        }
        await transporter.sendMail(mailOptions);
        emailHistory[senderEmail].push(Date.now());
        results.push({ success: true, recipient });
        sentSuccessfully = true;
        break;
      } catch (error) {
        lastError = error;
        attempts++;
      }
    }

    if (!sentSuccessfully) {
      results.push({ 
        success: false, 
        recipient, 
        error: lastError ? (lastError.message || "SMTP Send Error") : "SMTP Send Error" 
      });
    }

    if (index < recipients.length - 1) {
      // Short organic delay between emails to mimic natural human behavior
      await new Promise(r => setTimeout(r, 30 + Math.floor(Math.random() * 30)));
    }
  }

  for (const result of results) {
    if (result.success) sent++;
    else failed++;
  }

  res.json({
    success: true,
    results: { sent, failed },
    limitExceeded,
    message: limitExceeded ? "Mail Limit Full ❌" : undefined
  });
});

/* ==========================================================================
   STOP SEND PROCESS
   ========================================================================== */
app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Stopping future batches." });

  setTimeout(() => { activeSessions['global_stop'] = false; }, 5000);
});

/* ==========================================================================
   START SERVER
   ========================================================================== */
const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

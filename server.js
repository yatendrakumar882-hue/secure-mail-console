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

const SITE_PASSWORD = process.env.SITE_PASSWORD || '####';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const emailHistory = {};

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
   SMTP TRANSPORTER POOLING (Organic & Secure Settings)
   ========================================================================== */
const transporters = {};

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
        rejectUnauthorized: true // Secure TLS connection
      },
      family: 4,
      pool: true,
      maxConnections: 1, // Single connection for organic pacing
      maxMessages: 200
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
   SEND BATCH (100% Organic & Safe Delay)
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

  if (!emailHistory[senderEmail]) {
    emailHistory[senderEmail] = [];
  }
  emailHistory[senderEmail] = emailHistory[senderEmail].filter(ts => ts > oneHourAgo);

  const currentSentCount = emailHistory[senderEmail].length;
  if (currentSentCount >= 28) {
    return res.status(400).json({
      success: false,
      limitExceeded: true,
      message: `Mail Limit Full ❌ (Sent: ${currentSentCount}/28 in last hour)`
    });
  }

  const transporter = getTransporter(email, appPassword);
  let sent = 0;
  let failed = 0;
  let limitExceeded = false;

  const cleanSenderName = (senderName || "").replace(/["\r\n]/g, "").trim();
  const results = [];
  const allowedRemaining = 28 - currentSentCount;

  for (let index = 0; index < recipients.length; index++) {
    const recipient = recipients[index].trim();

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
    let spunBody = parseSpintax(messageBody);
    const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

    const domain = senderEmail.split('@')[1] || 'gmail.com';
    const messageId = `<${Date.now()}.${Math.random().toString(36).substring(2, 9)}@${domain}>`;

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
      to: recipient,
      replyTo: senderEmail,
      subject: spunSubject,
      headers: {
        'Message-ID': messageId,
        'X-Mailer': 'Secure Console Mailer',
        'Date': new Date().toUTCString()
      }
    };

    if (isHtml) {
      mailOptions.html = spunBody;
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
      await transporter.sendMail(mailOptions);
      emailHistory[senderEmail].push(Date.now());
      results.push({ success: true, recipient });
    } catch (error) {
      results.push({ success: false, recipient, error: error.message });
    }

    // 🟢 SAFE & ORGANIC DELAY: 3.5s to 6.0s (25 mails in ~1.5 to 2.5 mins)
    if (index < recipients.length - 1) {
      const delay = 3500 + Math.random() * 2500;
      await new Promise(res => setTimeout(res, delay));
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

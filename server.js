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
   NATURAL GMAIL TRANSPORTER POOLING
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
      pool: true,
      maxConnections: 3,
      maxMessages: 100
    });
  }
  return transporters[cacheKey];
}

/* ==========================================================================
   AUTHENTICATION ROUTE
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
   SMTP VERIFY ROUTE
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
   SPINTAX PARSER FOR DYNAMIC UNIQUE CONTENT
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
   CLEAN TEXT CONVERTER (FOR DUAL MULTIPART INBOX LANDING)
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
   1-BY-1 INBOX SAFE REALTIME SSE STREAM ROUTE
   ========================================================================== */
app.post("/api/send-stream", async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !recipients?.length) {
    res.write(`data: ${JSON.stringify({ success: false, error: "Missing required fields" })}\n\n`);
    res.end();
    return;
  }

  const senderEmail = email.toLowerCase().trim();
  const now = Date.now();
  const oneHourAgo = now - 3600000;

  if (!emailHistory[senderEmail]) {
    emailHistory[senderEmail] = [];
  }
  emailHistory[senderEmail] = emailHistory[senderEmail].filter(ts => ts > oneHourAgo);

  let currentSentCount = emailHistory[senderEmail].length;
  const transporter = getTransporter(email, appPassword);
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

  for (let index = 0; index < recipients.length; index++) {
    const recipient = recipients[index] ? recipients[index].trim() : "";
    if (!recipient) continue;

    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: "Stopped by user" })}\n\n`);
      continue;
    }

    if (currentSentCount >= 28) {
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: "Mail Limit Full ❌", limitExceeded: true })}\n\n`);
      continue;
    }

    const spunSubject = parseSpintax(subject);
    const spunBody = parseSpintax(messageBody);
    const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

    // Natural Mail Options - No Fake/Custom X-Headers!
    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
      to: recipient,
      replyTo: senderEmail,
      subject: spunSubject
    };

    if (isHtml) {
      mailOptions.html = spunBody;
      mailOptions.text = convertHtmlToText(spunBody);
    } else {
      mailOptions.text = spunBody;
    }

    let sentSuccessfully = false;
    let lastError = null;

    try {
      await transporter.sendMail(mailOptions);
      emailHistory[senderEmail].push(Date.now());
      currentSentCount++;
      sentSuccessfully = true;
    } catch (error) {
      lastError = error;
    }

    if (sentSuccessfully) {
      res.write(`data: ${JSON.stringify({ success: true, recipient })}\n\n`);
    } else {
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: lastError ? lastError.message : "SMTP Send Error" })}\n\n`);
    }

    // SAFE HUMAN DELAY: 1.5s to 3s per email (Prevents Gmail Bot Detection & Spam Filtering)
    if (index < recipients.length - 1) {
      const naturalDelay = 1500 + Math.floor(Math.random() * 1500);
      await new Promise(r => setTimeout(r, naturalDelay));
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
});

/* ==========================================================================
   STOP ROUTE
   ========================================================================== */
app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Stopping future sends." });

  setTimeout(() => { activeSessions['global_stop'] = false; }, 5000);
});

/* ==========================================================================
   SERVER INITIALIZATION
   ========================================================================== */
const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

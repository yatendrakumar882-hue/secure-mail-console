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
   HIGH-RELIABILITY TRANSPORTER CREATOR
   ========================================================================== */
function createTransporter(email, appPassword) {
  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true, // Direct SSL for high stability & bypass TLS handshake errors
    auth: {
      user: email,
      pass: appPassword
    },
    authMethod: 'PLAIN',
    connectionTimeout: 10000, // 10s timeout
    greetingTimeout: 10000,
    socketTimeout: 10000
  });
}

/* ==========================================================================
   VERIFY SMTP CREDENTIALS
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
    const transporter = createTransporter(email, appPassword);
    await transporter.verify();

    res.json({
      success: true,
      message: "SMTP verified successfully"
    });
  } catch (error) {
    console.error("SMTP Verify Failure:", error.message);
    res.status(401).json({
      success: false,
      message: `Verification Failed: ${error.message}`
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
   SINGLE MAIL SEND ENDPOINT (With Retry & Fail-safe)
   ========================================================================== */
app.post("/api/send-single", async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipient } = req.body;

  if (!email || !appPassword || !recipient) {
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

  if (activeSessions['global_stop']) {
    return res.json({ success: false, error: "Stopped by user" });
  }

  const cleanSenderName = (senderName || "").replace(/["\r\n]/g, "").trim();
  const spunSubject = parseSpintax(subject);
  let spunBody = parseSpintax(messageBody);
  const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

  const domain = senderEmail.split('@')[1] || 'gmail.com';
  const randomStr = Math.random().toString(36).substring(2, 9);
  const messageId = `<${Date.now()}.${randomStr}@${domain}>`;

  const mailOptions = {
    from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
    to: recipient.trim(),
    replyTo: senderEmail,
    subject: spunSubject,
    headers: {
      'Message-ID': messageId,
      'X-Mailer': 'Secure Mail Console',
      'Date': new Date().toUTCString(),
      'X-Priority': '3',
      'Importance': 'Normal'
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

  const transporter = createTransporter(email, appPassword);

  // Auto Retry Loop (Max 2 Attempts for High Deliverability)
  let attempts = 0;
  let lastError = null;

  while (attempts < 2) {
    try {
      await transporter.sendMail(mailOptions);
      emailHistory[senderEmail].push(Date.now());
      return res.json({ success: true, recipient });
    } catch (error) {
      lastError = error;
      attempts++;
      console.warn(`Attempt ${attempts} failed for ${recipient}: ${error.message}`);
      if (attempts < 2) {
        await new Promise(r => setTimeout(r, 1000)); // Delay 1 sec before retrying
      }
    }
  }

  console.error(`[SEND FAILED] Recipient: ${recipient} | Error:`, lastError?.message);
  return res.status(500).json({ 
    success: false, 
    recipient, 
    error: lastError ? lastError.message : "SMTP Send Failed" 
  });
});

/* ==========================================================================
   STOP SEND PROCESS
   ========================================================================== */
app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Stopping future sends." });
  setTimeout(() => { activeSessions['global_stop'] = false; }, 5000);
});

/* ==========================================================================
   START SERVER
   ========================================================================== */
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

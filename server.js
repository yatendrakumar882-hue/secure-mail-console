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
      service: "gmail",
      auth: {
        user: email,
        pass: appPassword
      },
      pool: true,             // Enable connection pooling for ultra-fast reuse
      maxConnections: 5,      // Standard concurrent pool connections
      maxMessages: 100
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

/**
 * Automatically personalizes and naturalizes each email's content.
 * Bypasses incoming bulk spam detectors (which block identical content sent to multiple accounts)
 * by dynamically applying organic greetings, polite human closings, and weekday variations.
 * Does NOT use suspicious hidden span elements or weird tracking code tags that raise spam score.
 */
function naturalizeEmailContent(subject, body, senderName, index) {
  let spunSubject = parseSpintax(subject);
  let spunBody = parseSpintax(body);

  const cleanSender = (senderName || "").trim();

  // 1. Automatic polite greeting if none is present
  const hasGreeting = /^(hello|hi|dear|greetings|hey|good\s+(morning|afternoon|evening))/i.test(spunBody.trim());
  const greetings = [
    "Hello,",
    "Hi,",
    "Greetings,",
    "Dear,",
    "Hello there,",
    "Hi there,",
    "Good day,"
  ];

  if (!hasGreeting) {
    const chosenGreeting = greetings[index % greetings.length];
    spunBody = `${chosenGreeting}\n\n${spunBody}`;
  }

  // 2. High-reputation friendly weekday/time signature
  const daysOfWeek = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  const currentDay = daysOfWeek[new Date().getDay()];

  const wishes = [
    `Hope you have a wonderful ${currentDay}!`,
    `Wishing you a very productive ${currentDay}!`,
    `Hope you are having a great ${currentDay}!`,
    `Wishing you a wonderful week ahead!`,
    `Hope your day is going exceptionally well!`,
    `Have a wonderful rest of your day!`,
    `Wishing you all the best and success!`,
    `Hope this email finds you in high spirits!`
  ];

  const closings = [
    `Best regards,\n${cleanSender}`,
    `Thanks and regards,\n${cleanSender}`,
    `Sincerely,\n${cleanSender}`,
    `Warmly,\n${cleanSender}`,
    `With warm appreciation,\n${cleanSender}`,
    `Kind regards,\n${cleanSender}`,
    `Best wishes,\n${cleanSender}`,
    `Respectfully,\n${cleanSender}`
  ];

  const chosenWish = wishes[index % wishes.length];
  const chosenClosing = closings[index % closings.length];

  // Append wishes and closings naturally to the email body
  spunBody = `${spunBody}\n\n${chosenWish}\n\n${chosenClosing}`;

  // 3. Subtle micro-variation in spacing and punctuation to ensure unique email hashes
  if (index % 2 === 0) {
    spunBody += " ";
  } else {
    spunBody += "\n";
  }

  // Micro-variation in subject line using subtle styling or character suffix
  const subjectVariations = ["", " ", ".", " !", "...", " "];
  spunSubject = `${spunSubject}${subjectVariations[index % subjectVariations.length]}`;

  return { subject: spunSubject, body: spunBody };
}

/* ==========================================================================
   SEND BATCH (STANDARD AND STREAMING)
   ========================================================================== */

/**
 * Standard batch route
 */
app.post("/api/send-batch", async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;

  if (!email || !appPassword || !recipients?.length) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields"
    });
  }

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

    // Apply natural automatic content variations for subject and body
    const { subject: naturalSubject, body: naturalBody } = naturalizeEmailContent(subject, messageBody, cleanSenderName, index);
    const isHtml = /<[a-z][\s\S]*>/i.test(naturalBody);

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${email}>` : email,
      to: recipient,
      replyTo: email,
      subject: naturalSubject
    };

    if (isHtml) {
      mailOptions.html = naturalBody;
      const textFallback = naturalBody
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
      mailOptions.text = naturalBody;
    }

    let sentSuccessfully = false;
    let lastError = null;
    let attempts = 0;
    const maxAttempts = 2;

    while (attempts < maxAttempts) {
      try {
        if (attempts > 0) {
          await new Promise(res => setTimeout(res, 200 + Math.random() * 200));
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
      results.push({ success: false, recipient, error: lastError ? lastError.message : "SMTP Send Error" });
    }

    if (index < recipients.length - 1) {
      // Fast micro-stagger delay (100ms - 200ms) keeps SMTP pool warm and sends ultra-fast
      await new Promise(res => setTimeout(res, 100 + Math.random() * 100));
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

/**
 * High-speed Server-Sent Events (SSE) streaming route
 * Sends 1-by-1 sequentially on the server side with warm pools,
 * and streams results instantly to the client in real-time.
 */
app.post("/api/send-stream", async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;

  if (!email || !appPassword || !recipients?.length) {
    res.write(`data: ${JSON.stringify({ success: false, error: "Missing required fields" })}\n\n`);
    res.end();
    return;
  }

  if (cfToken && TURNSTILE_SECRET_KEY) {
    const isValidToken = await verifyTurnstile(cfToken, req.ip);
    if (!isValidToken) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Spam check failed. Try again." })}\n\n`);
      res.end();
      return;
    }
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
  const allowedRemaining = 28 - currentSentCount;

  for (let index = 0; index < recipients.length; index++) {
    const recipient = recipients[index] ? recipients[index].trim() : "";
    if (!recipient) continue;

    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: "Stopped by user" })}\n\n`);
      continue;
    }

    if (currentSentCount >= 28 || index >= allowedRemaining) {
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: "Mail Limit Full ❌", limitExceeded: true })}\n\n`);
      continue;
    }

    // Apply natural automatic content variations for subject and body
    const { subject: naturalSubject, body: naturalBody } = naturalizeEmailContent(subject, messageBody, cleanSenderName, index);
    const isHtml = /<[a-z][\s\S]*>/i.test(naturalBody);

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${email}>` : email,
      to: recipient,
      replyTo: email,
      subject: naturalSubject
    };

    if (isHtml) {
      mailOptions.html = naturalBody;
      const textFallback = naturalBody
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
      mailOptions.text = naturalBody;
    }

    let sentSuccessfully = false;
    let lastError = null;
    let attempts = 0;
    const maxAttempts = 2;

    while (attempts < maxAttempts) {
      try {
        if (attempts > 0) {
          await new Promise(res => setTimeout(res, 200 + Math.random() * 200));
        }
        await transporter.sendMail(mailOptions);
        emailHistory[senderEmail].push(Date.now());
        currentSentCount++;
        sentSuccessfully = true;
        break;
      } catch (error) {
        lastError = error;
        attempts++;
      }
    }

    if (sentSuccessfully) {
      res.write(`data: ${JSON.stringify({ success: true, recipient })}\n\n`);
    } else {
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: lastError ? lastError.message : "SMTP Send Error" })}\n\n`);
    }

    if (index < recipients.length - 1) {
      // Fast micro-stagger delay (100ms - 200ms) keeps SMTP pool warm and sends ultra-fast
      await new Promise(res => setTimeout(res, 100 + Math.random() * 100));
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
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

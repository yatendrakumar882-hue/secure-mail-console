import 'dotenv/config';
import express from 'express';
import http from 'http';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

// ES Module Directory Resolution
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);

// Configuration Constants
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

const activeSessions = {};
const transporters = new Map();

// Express Middlewares
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

/* ==========================================================================
   UTILITY & HELPER FUNCTIONS
   ========================================================================== */

// Cloudflare Turnstile Verification Helper
async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY) return true;
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: TURNSTILE_SECRET_KEY, response: token, remoteip: ip })
    });
    const data = await response.json();
    return data.success;
  } catch (error) {
    console.error('Turnstile verification error:', error);
    return false;
  }
}

// SMTP Transporter Pooling (Optimized Socket Pool)
function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPassword = appPassword.replace(/\s+/g, '').trim();
  const cacheKey = `${cleanEmail}_${cleanPassword}`;

  if (!transporters.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: cleanEmail,
        pass: cleanPassword
      },
      pool: true,
      maxConnections: 8,
      maxMessages: 100
    });
    transporters.set(cacheKey, transporter);
  }
  return transporters.get(cacheKey);
}

// Spintax Text Parser ({Option 1|Option 2})
function parseSpintax(text) {
  if (!text) return "";
  let spun = text;
  const regex = /{([^{}]+)}/g;
  let iterations = 0;
  while (regex.test(spun) && iterations < 10) {
    spun = spun.replace(regex, (_, choices) => {
      const options = choices.split('|');
      return options[Math.floor(Math.random() * options.length)];
    });
    iterations++;
  }
  return spun;
}

// Safe Array Chunking Helper
function chunkArray(array, chunkSize) {
  const chunks = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    chunks.push(array.slice(i, i + chunkSize));
  }
  return chunks;
}

/* ==========================================================================
   API ENDPOINTS
   ========================================================================== */

// Serve Frontend Home
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Admin Password Verification
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

// Verify SMTP Connection
app.post("/api/verify", async (req, res) => {
  const { email, appPassword, cfToken } = req.body;

  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: "Email and App Password required" });
  }

  if (cfToken && TURNSTILE_SECRET_KEY) {
    const isValid = await verifyTurnstile(cfToken, req.ip);
    if (!isValid) {
      return res.status(400).json({ success: false, message: "Turnstile check failed." });
    }
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: "SMTP verified successfully" });
  } catch (error) {
    console.error("SMTP Verify Error:", error);
    return res.status(401).json({ success: false, message: error.message || "Authentication failed" });
  }
});

// SSE Email Batch Stream Route (Safe 8 Parallel Batch Execution)
app.post("/api/send-stream", async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: "Missing required fields" })}\n\n`);
    res.end();
    return;
  }

  if (cfToken && TURNSTILE_SECRET_KEY) {
    const isValid = await verifyTurnstile(cfToken, req.ip);
    if (!isValid) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Turnstile check failed" })}\n\n`);
      res.end();
      return;
    }
  }

  const senderEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

  activeSessions['global_stop'] = false;

  const validRecipients = recipients
    .map(r => (r ? r.trim() : ''))
    .filter(r => r.length > 0);

  const BATCH_SIZE = 8;
  const batches = chunkArray(validRecipients, BATCH_SIZE);
  const transporter = getTransporter(email, appPassword);

  for (let bIndex = 0; bIndex < batches.length; bIndex++) {
    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Stopped by user" })}\n\n`);
      break;
    }

    const currentBatch = batches[bIndex];
    res.write(': keep-alive\n\n');

    const batchPromises = currentBatch.map(async (recipient) => {
      try {
        const spunSubject = parseSpintax(subject);
        const spunBody = parseSpintax(messageBody);
        const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
          to: recipient,
          replyTo: senderEmail,
          subject: spunSubject || "No Subject",
          headers: {
            'Date': new Date().toUTCString(),
            'X-Mailer': 'Gmail'
          }
        };

        if (isHtml) {
          mailOptions.html = spunBody;
          mailOptions.text = spunBody.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
        } else {
          mailOptions.text = spunBody;
        }

        await transporter.sendMail(mailOptions);
        res.write(`data: ${JSON.stringify({ success: true, recipient })}\n\n`);
      } catch (error) {
        console.error(`Error sending to ${recipient}:`, error.message);
        res.write(`data: ${JSON.stringify({ success: false, recipient, error: error.message })}\n\n`);
      }
    });

    await Promise.all(batchPromises);

    if (bIndex < batches.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, 2500));
    }
  }

  res.write('data: [DONE]\n\n');
  res.end();
});

// Stop Execution Handler
app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Stop process registered" });
  setTimeout(() => { activeSessions['global_stop'] = false; }, 5000);
});

/* ==========================================================================
   SERVER INITIALIZATION
   ========================================================================== */

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

export default app;

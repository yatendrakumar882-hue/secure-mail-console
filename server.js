import 'dotenv/config';
import express from 'express';
import http from 'http';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

// Directory Path Setup
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);

// Configuration Constants
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

// Batch size: 10 emails ek saath (25 emails ~3 batches mein poore honge)
const PARALLEL_BATCH_SIZE = 10; 

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
    console.error('Turnstile Verification Error:', error);
    return false;
  }
}

// Strict Email Regex Validator
function isValidEmail(email) {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(email);
}

// Transporter Socket Pooling (10 Parallel Connections for Multi-Socket Blasts)
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
      maxConnections: 10, // 10 Parallel sockets for batch blasts
      maxMessages: 100,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    transporters.set(cacheKey, transporter);
  }
  return transporters.get(cacheKey);
}

// Spintax Text Engine ({Hi|Hello|Hey})
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

// Personalization Engine ({name})
function replacePersonalization(text, recipientEmail) {
  if (!text) return "";
  const namePart = recipientEmail.split('@')[0].split('.')[0].replace(/[^a-zA-Z]/g, '');
  const capitalizedName = namePart ? namePart.charAt(0).toUpperCase() + namePart.slice(1) : "Customer";
  return text.replace(/{name}/gi, capitalizedName);
}

// Unique RFC 5322 Message-ID
function generateMessageId(domain) {
  const randomStr = Math.random().toString(36).substring(2, 11);
  return `<${Date.now()}.${randomStr}@${domain}>`;
}

// HTML to Clean Plain-Text Converter
function convertHtmlToCleanText(html) {
  if (!html) return "";
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// Helper Array Chunking (Splits Array into Batches of 10)
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

// Root Route
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

// Verify SMTP Credentials
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

// Parallel Batch Stream Endpoint (10 Emails Parallel Per Burst)
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
  const domainPart = senderEmail.split('@')[1] || 'gmail.com';
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

  activeSessions['global_stop'] = false;

  const validRecipients = recipients
    .map(r => (r ? r.trim() : ''))
    .filter(r => r.length > 0 && isValidEmail(r));

  if (validRecipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: "No valid recipient email addresses found" })}\n\n`);
    res.end();
    return;
  }

  const transporter = getTransporter(email, appPassword);
  
  // Split 25 recipients into ~3 batches of 10
  const batches = chunkArray(validRecipients, PARALLEL_BATCH_SIZE);

  for (let bIndex = 0; bIndex < batches.length; bIndex++) {
    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Stopped by user" })}\n\n`);
      break;
    }

    const currentBatch = batches[bIndex];
    res.write(': keep-alive\n\n');

    // Fire 10 emails SIMULTANEOUSLY in parallel
    const batchPromises = currentBatch.map(async (recipient) => {
      try {
        let spunSubject = parseSpintax(subject);
        let spunBody = parseSpintax(messageBody);

        spunSubject = replacePersonalization(spunSubject, recipient);
        spunBody = replacePersonalization(spunBody, recipient);

        const isHtmlText = /<[a-z][\s\S]*>/i.test(spunBody);
        const cleanPlainContent = convertHtmlToCleanText(spunBody);

        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
          to: recipient,
          replyTo: senderEmail,
          subject: spunSubject || "No Subject",
          messageId: generateMessageId(domainPart),
          text: cleanPlainContent,
          headers: {
            'Date': new Date().toUTCString(),
            'X-Mailer': 'Gmail',
            'X-Priority': '3',
            'Importance': 'normal'
          }
        };

        if (isHtmlText) {
          mailOptions.html = spunBody;
        }

        await transporter.sendMail(mailOptions);
        res.write(`data: ${JSON.stringify({ success: true, recipient })}\n\n`);

      } catch (error) {
        console.error(`Error sending to ${recipient}:`, error.message);
        res.write(`data: ${JSON.stringify({ success: false, recipient, error: error.message })}\n\n`);
      }
    });

    // Wait for the entire batch of 10 to finish sending
    await Promise.all(batchPromises);

    // Micro 300ms break between batch bursts
    if (bIndex < batches.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
  }

  res.write('data: [DONE]\n\n');
  res.end();
});

// Stop Execution Endpoint
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

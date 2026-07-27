import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

// Express Middleware
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const transporters = new Map();

/* Root Route */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* Turnstile Verification */
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
    return false;
  }
}

/* Transporter Connection Pooling */
function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPassword = appPassword.replace(/\s+/g, '').trim();
  const cacheKey = `${cleanEmail}_${cleanPassword}`;

  if (!transporters.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: cleanEmail, pass: cleanPassword },
      pool: true,
      maxConnections: 1,
      maxMessages: 50
    });
    transporters.set(cacheKey, transporter);
  }
  return transporters.get(cacheKey);
}

/* Recursive Spintax Parser */
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

/* HTML to Clean Plain Text Engine */
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
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\n\s*\n/g, '\n\n')
    .trim();
}

/* Auth Routes */
app.post("/api/auth", (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true, message: "Access granted" });
  return res.status(401).json({ success: false, message: "Incorrect password" });
});

app.post("/api/verify", async (req, res) => {
  const { email, appPassword, cfToken } = req.body;
  if (!email || !appPassword) return res.status(400).json({ success: false, message: "Credentials required" });

  if (cfToken && TURNSTILE_SECRET_KEY) {
    const isValidToken = await verifyTurnstile(cfToken, req.ip);
    if (!isValidToken) return res.status(400).json({ success: false, message: "Turnstile security check failed." });
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: "SMTP verified successfully" });
  } catch (error) {
    return res.status(401).json({ success: false, message: "Authentication failed. Check App Password." });
  }
});

/* SSE Stream Route */
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
    const isValidToken = await verifyTurnstile(cfToken, req.ip);
    if (!isValidToken) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Turnstile verification failed" })}\n\n`);
      res.end();
      return;
    }
  }

  const senderEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

  activeSessions['global_stop'] = false;

  for (let index = 0; index < recipients.length; index++) {
    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Stopped by user" })}\n\n`);
      break;
    }

    const recipient = recipients[index] ? recipients[index].trim() : "";
    if (!recipient) continue;

    res.write(': keep-alive\n\n');

    try {
      const transporter = getTransporter(email, appPassword);
      const spunSubject = parseSpintax(subject);
      const spunBody = parseSpintax(messageBody);
      const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

      const mailOptions = {
        from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
        to: recipient,
        subject: spunSubject,
        headers: {
          'X-Mailer': 'Gmail',
          'Date': new Date().toUTCString()
        }
      };

      if (isHtml) {
        mailOptions.html = spunBody;
        mailOptions.text = convertHtmlToCleanText(spunBody);
      } else {
        mailOptions.text = spunBody;
      }

      await transporter.sendMail(mailOptions);
      res.write(`data: ${JSON.stringify({ success: true, recipient })}\n\n`);

    } catch (error) {
      console.error(`Error sending to ${recipient}:`, error.message);
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: error.message })}\n\n`);
    }

    // Natural Delay Interval (3s - 5s)
    if (index < recipients.length - 1) {
      const randomDelay = Math.floor(300 + Math.random() * 200);
      await new Promise(resolve => setTimeout(resolve, randomDelay));
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
});

app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Stop process registered" });
});

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

export default app;

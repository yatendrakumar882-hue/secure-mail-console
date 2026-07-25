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

// Middleware
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const transporters = new Map();

/* Turnstile Verification */
async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY || !token) return true;
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: TURNSTILE_SECRET_KEY, response: token, remoteip: ip || '' })
    });
    const data = await response.json();
    return data.success;
  } catch (error) {
    return false;
  }
}

/* Dynamic Transporter with Pool */
function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cacheKey = `${cleanEmail}_${appPassword}`;

  if (!transporters.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: cleanEmail, pass: appPassword },
      pool: true,
      maxConnections: 3,
      maxMessages: 100,
      rateDelta: 1000,
      rateLimit: 1
    });
    transporters.set(cacheKey, transporter);
  }
  return transporters.get(cacheKey);
}

/* Spintax Parser */
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

/* Clean Plain Text Converter for Dual Multipart */
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
    .replace(/\n\s*\n/g, '\n\n')
    .trim();
}

/* Routes */
app.post("/api/auth", (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true });
  return res.status(401).json({ success: false, message: "Incorrect password" });
});

app.post("/api/verify", async (req, res) => {
  const { email, appPassword, cfToken } = req.body;
  if (!email || !appPassword) return res.status(400).json({ success: false, message: "Credentials required" });

  if (cfToken && TURNSTILE_SECRET_KEY) {
    const isValidToken = await verifyTurnstile(cfToken, req.ip);
    if (!isValidToken) return res.status(400).json({ success: false, message: "Captcha check failed" });
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: "SMTP verified" });
  } catch (error) {
    return res.status(401).json({ success: false, message: "Authentication failed. Invalid App Password." });
  }
});

/* Reliable SSE Stream Route */
app.post("/api/send-stream", async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: "Missing fields" })}\n\n`);
    res.end();
    return;
  }

  let clientDisconnected = false;
  req.on('close', () => { clientDisconnected = true; });

  const senderEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();
  activeSessions['global_stop'] = false;

  for (let index = 0; index < recipients.length; index++) {
    if (clientDisconnected || activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Stopped" })}\n\n`);
      break;
    }

    const recipient = recipients[index] ? recipients[index].trim() : "";
    if (!recipient) continue;

    const transporter = getTransporter(email, appPassword);
    const spunSubject = parseSpintax(subject);
    const spunBody = parseSpintax(messageBody);
    const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
      to: recipient,
      subject: spunSubject
    };

    if (isHtml) {
      mailOptions.html = spunBody;
      mailOptions.text = convertHtmlToText(spunBody);
    } else {
      mailOptions.text = spunBody;
    }

    let sent = false;
    let retries = 2; // Auto Retry Mechanism if network glitches

    while (retries > 0 && !sent) {
      try {
        await transporter.sendMail(mailOptions);
        sent = true;
        res.write(`data: ${JSON.stringify({ success: true, recipient })}\n\n`);
      } catch (error) {
        retries--;
        if (retries === 0) {
          res.write(`data: ${JSON.stringify({ success: false, recipient, error: error.message })}\n\n`);
        } else {
          await new Promise(r => setTimeout(r, 1000)); // Wait before retry
        }
      }
    }

    // Safe Organic Delay (0.2 seconds per mail to clear Gmail throttle & Inbox placement)
    if (index < recipients.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
});

app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

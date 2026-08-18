import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const SITE_PASSWORD = process.env.SITE_PASSWORD || 'admin123';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

// Express Setup
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const transporterPool = new Map();

/* ==========================================================================
   TRANSPORTER POOL (Pure SSL Socket Reuse)
   ========================================================================== */
function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cacheKey = `${cleanEmail}_${appPassword}`;

  if (!transporterPool.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: cleanEmail,
        pass: appPassword
      },
      pool: true,
      maxConnections: 3,
      maxMessages: 100
    });
    transporterPool.set(cacheKey, transporter);
  }
  return transporterPool.get(cacheKey);
}

/* ==========================================================================
   DEEP SPINTAX PARSER (Handles Multiline & Nested Syntax Cleanly)
   ========================================================================== */
function parseSpintax(text) {
  if (!text) return "";
  let spun = String(text);
  const regex = /\{([^{}]+)\}/s;
  let iterations = 0;

  while (regex.test(spun) && iterations < 40) {
    spun = spun.replace(regex, (_, choices) => {
      const options = choices.split('|');
      const pick = options[Math.floor(Math.random() * options.length)];
      return pick ? pick.trim() : "";
    });
    iterations++;
  }

  return spun.replace(/[\{\}]/g, '').trim();
}

/* ==========================================================================
   HTML TO CLEAN PLAIN TEXT
   ========================================================================== */
function convertHtmlToCleanText(html) {
  if (!html) return "";
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<br\s*[\/]?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\n\s*\n/g, '\n\n')
    .trim();
}

/* ==========================================================================
   AUTH & VERIFICATION ROUTES
   ========================================================================== */
app.post("/api/auth", (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true });
  return res.status(401).json({ success: false, message: "Incorrect password" });
});

app.post("/api/verify", async (req, res) => {
  const { email, appPassword } = req.body;
  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: "Credentials required" });
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: "SMTP connection verified" });
  } catch (error) {
    return res.status(401).json({ success: false, message: "SMTP Authentication failed. Check App Password." });
  }
});

/* ==========================================================================
   PRIMARY INBOX SEND STREAM ROUTE
   ========================================================================== */
app.post("/api/send-stream", async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: "Missing required fields" })}\n\n`);
    res.end();
    return;
  }

  const senderEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || "").replace(/["\r\n]/g, "").trim();
  const fromAddress = cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail;

  activeSessions['global_stop'] = false;
  const transporter = getTransporter(email, appPassword);

  for (let index = 0; index < recipients.length; index++) {
    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Stopped by user" })}\n\n`);
      break;
    }

    const recipient = (recipients[index] || "").trim();
    if (!recipient) continue;

    res.write(': keep-alive\n\n');

    try {
      // Dynamic Generation per recipient
      const spunSubject = parseSpintax(subject);
      const spunBody = parseSpintax(messageBody);
      const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

      // Clean, Trusted Sign-off Footer
      const plainFooter = `\n\n---\nBest,\n${cleanSenderName || 'Support'}\nReply 'unsubscribe' to opt out.`;
      const htmlFooter = `<br><br><div style="font-size:12px;color:#888;border-top:1px solid #eaeaea;padding-top:8px;margin-top:16px;">Best,<br><strong>${cleanSenderName || 'Support'}</strong><br><span style="color:#aaa;font-size:11px;">Reply 'unsubscribe' to opt out.</span></div>`;

      const mailOptions = {
        from: fromAddress,
        to: recipient,
        subject: spunSubject,
        date: new Date()
      };

      if (isHtml) {
        mailOptions.html = spunBody + htmlFooter;
        mailOptions.text = convertHtmlToCleanText(spunBody) + plainFooter;
      } else {
        mailOptions.text = spunBody + plainFooter;
      }

      await transporter.sendMail(mailOptions);
      res.write(`data: ${JSON.stringify({ success: true, recipient })}\n\n`);
    } catch (error) {
      console.error(`Error sending to ${recipient}:`, error.message);
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: error.message })}\n\n`);
    }

    // Natural Safe Connection Delay (120ms)
    if (index < recipients.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 120));
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
  res.json({ success: true, message: "Stop process registered" });
});

export default app;

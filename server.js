import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const SITE_PASSWORD = process.env.SITE_PASSWORD || '##';

// Express Middleware Setup
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const transporters = new Map();

/* ==========================================================================
   TRANSPORTER POOLING (TLS Socket Reuse & Concurrency Optimized)
   ========================================================================== */
function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cacheKey = `${cleanEmail}_${appPassword}`;

  if (!transporters.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: cleanEmail, pass: appPassword },
      pool: true,
      maxConnections: 6, // 6 parallel connections for fast concurrent delivery
      maxMessages: 200,
      rateLimit: 10 // Safe rate per second
    });
    transporters.set(cacheKey, transporter);
  }
  return transporters.get(cacheKey);
}

/* ==========================================================================
   SPINTAX PARSER ({Hi|Hello|Hey})
   ========================================================================== */
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

/* ==========================================================================
   HTML TO PLAIN-TEXT FALLBACK (Dual Multipart MIME for Deliverability)
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
    .replace(/\n\s*\n/g, '\n\n')
    .trim();
}

/* ==========================================================================
   AUTHENTICATION & VERIFY ROUTES
   ========================================================================== */
app.post("/api/auth", (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true });
  return res.status(401).json({ success: false, message: "Incorrect password" });
});

app.post("/api/verify", async (req, res) => {
  const { email, appPassword } = req.body;
  if (!email || !appPassword) return res.status(400).json({ success: false, message: "Credentials required" });

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: "SMTP verified successfully" });
  } catch (error) {
    return res.status(401).json({ success: false, message: "Authentication failed. Check App Password." });
  }
});

/* ==========================================================================
   SSE STREAM ROUTE (BATCH OF 6 PARALLEL EMAILS + INBOX HEADERS)
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
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();
  const domainPart = senderEmail.split('@')[1] || 'gmail.com';

  activeSessions['global_stop'] = false;
  const transporter = getTransporter(email, appPassword);

  const BATCH_SIZE = 6; // Ek saath 6 emails process honge

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Stopped by user" })}\n\n`);
      break;
    }

    // Keep-alive ping
    res.write(': keep-alive\n\n');

    const batch = recipients.slice(i, i + BATCH_SIZE);

    // 6 emails parallel send honge
    const sendPromises = batch.map(async (recipientItem) => {
      const recipient = recipientItem ? recipientItem.trim() : "";
      if (!recipient) return null;

      try {
        const spunSubject = parseSpintax(subject);
        const spunBody = parseSpintax(messageBody);
        const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

        // Deliverability Headers (Inbox landing ke liye)
        const uniqueMessageId = `<${crypto.randomBytes(16).toString('hex')}@${domainPart}>`;

        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
          to: recipient,
          subject: spunSubject,
          messageId: uniqueMessageId,
          date: new Date(),
          headers: {
            'X-Mailer': 'SecureMail Client v1.0',
            'X-Priority': '3',
            'Importance': 'Normal'
          }
        };

        if (isHtml) {
          mailOptions.html = spunBody;
          mailOptions.text = convertHtmlToText(spunBody);
        } else {
          mailOptions.text = spunBody;
        }

        await transporter.sendMail(mailOptions);
        return { success: true, recipient };
      } catch (error) {
        console.error(`Error sending to ${recipient}:`, error.message);
        return { success: false, recipient, error: error.message };
      }
    });

    const results = await Promise.allSettled(sendPromises);

    for (const resItem of results) {
      if (resItem.status === 'fulfilled' && resItem.value) {
        res.write(`data: ${JSON.stringify(resItem.value)}\n\n`);
      }
    }

    // Chhota gap batches ke beech taaki Gmail connection drop na kare
    if (i + BATCH_SIZE < recipients.length) {
      await new Promise(resolve => setTimeout(resolve, 80));
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

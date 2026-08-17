import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

const SITE_PASSWORD = process.env.SITE_PASSWORD || '##';

// Middleware
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const transporterPool = new Map();

/* ==========================================================================
   TRANSPORTER CONFIGURATION
   ========================================================================== */
function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cacheKey = `${cleanEmail}_${appPassword}`;

  if (!transporterPool.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true, // SSL for clean handshake
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
   PLAIN TEXT CLEANER
   ========================================================================== */
function sanitizeToPlainText(content) {
  if (!content) return "";
  return content
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<br\s*[\/]?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .trim();
}

/* ==========================================================================
   ROUTES
   ========================================================================== */
app.post("/api/auth", (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) {
    return res.json({ success: true });
  }
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
    return res.json({ success: true, message: "SMTP credentials verified" });
  } catch (error) {
    return res.status(401).json({ success: false, message: "SMTP verification failed. Check App Password." });
  }
});

/* ==========================================================================
   STREAMING DISPATCH ROUTE
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
  const fromHeader = cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail;

  activeSessions['global_stop'] = false;
  const transporter = getTransporter(email, appPassword);

  const cleanBody = messageBody.trim();
  const isHtml = /<[a-z][\s\S]*>/i.test(cleanBody);
  const plainTextVersion = isHtml ? sanitizeToPlainText(cleanBody) : cleanBody;

  // Batch configuration: 3 concurrent sends with natural interval to preserve sender reputation
  const BATCH_SIZE = 3;

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Stopped by user" })}\n\n`);
      break;
    }

    res.write(': keep-alive\n\n');
    const batch = recipients.slice(i, i + BATCH_SIZE);

    const promises = batch.map(async (recipientEmail) => {
      const recipient = (recipientEmail || "").trim();
      if (!recipient) return null;

      try {
        const mailOptions = {
          from: fromHeader,
          to: recipient,
          subject: subject.trim(),
          text: plainTextVersion,
          encoding: 'quoted-printable',
          headers: {
            'X-Priority': '3',
            'Importance': 'Normal'
          }
        };

        if (isHtml) {
          mailOptions.html = cleanBody;
        }

        await transporter.sendMail(mailOptions);
        return { success: true, recipient };
      } catch (err) {
        return { success: false, recipient, error: err.message };
      }
    });

    const results = await Promise.allSettled(promises);

    for (const resItem of results) {
      if (resItem.status === 'fulfilled' && resItem.value) {
        res.write(`data: ${JSON.stringify(resItem.value)}\n\n`);
      }
    }

    // Deliverability delay (250ms) between batches to prevent spam-trigger throttling
    if (i + BATCH_SIZE < recipients.length) {
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
});

app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Process stopped" });
});

export default app;

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

// Express Setup
app.use(cors());
app.use(express.json({ limit: "20mb" }));
app.use(express.static(path.join(__dirname, "public")));

const activeSessions = {};
const transporterPool = new Map();

/* ==========================================================================
   TRANSPORTER WITH OPTIMIZED CONNECTION POOL
   ========================================================================== */
function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cacheKey = `${cleanEmail}_${appPassword}`;

  if (!transporterPool.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true, // TLS encrypted connection
      auth: { 
        user: cleanEmail, 
        pass: appPassword 
      },
      pool: true,
      maxConnections: 3, // Safe connection limit to prevent Gmail throttling
      maxMessages: 100
    });
    transporterPool.set(cacheKey, transporter);
  }
  return transporterPool.get(cacheKey);
}

/* ==========================================================================
   SPINTAX ENGINE (Prevents Content Fingerprinting)
   Usage in text: {Hi|Hello|Dear} {User|Friend}
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
   CLEAN PLAIN-TEXT FALLBACK (Ensures clean inbox score)
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
   AUTH & VERIFY ENDPOINTS
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
    return res.json({ success: true, message: "SMTP connection healthy and authenticated" });
  } catch (error) {
    return res.status(401).json({ success: false, message: "SMTP Authentication failed. Check 16-char App Password." });
  }
});

/* ==========================================================================
   SAFE STREAM DISPATCH (HIGH DELIVERABILITY PACING)
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

  // Safe batching: 2 emails at once with natural spacing
  const BATCH_SIZE = 2;

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, error: "Stopped by user" })}\n\n`);
      break;
    }

    res.write(': keep-alive\n\n');
    const batch = recipients.slice(i, i + BATCH_SIZE);

    const sendTasks = batch.map(async (recipientItem) => {
      const recipient = (recipientItem || "").trim();
      if (!recipient) return null;

      try {
        const dynamicSubject = parseSpintax(subject.trim());
        const dynamicBody = parseSpintax(messageBody.trim());
        const isHtml = /<[a-z][\s\S]*>/i.test(dynamicBody);

        const mailOptions = {
          from: fromHeader,
          to: recipient,
          subject: dynamicSubject,
          date: new Date()
        };

        if (isHtml) {
          mailOptions.html = dynamicBody;
          mailOptions.text = convertHtmlCleanText(dynamicBody);
        } else {
          mailOptions.text = dynamicBody;
        }

        await transporter.sendMail(mailOptions);
        return { success: true, recipient };
      } catch (err) {
        console.error(`Send error to ${recipient}:`, err.message);
        return { success: false, recipient, error: err.message };
      }
    });

    const results = await Promise.allSettled(sendTasks);

    for (const item of results) {
      if (item.status === 'fulfilled' && item.value) {
        res.write(`data: ${JSON.stringify(item.value)}\n\n`);
      }
    }

    // Natural pacing delay: 500ms - 800ms (Prevents IP rate-limiting & spam flagging)
    if (i + BATCH_SIZE < recipients.length) {
      const naturalDelay = Math.floor(Math.random() * 300) + 500;
      await new Promise(resolve => setTimeout(resolve, naturalDelay));
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
});

app.post("/api/stop", (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: "Stop process registered" });
});

export default app;

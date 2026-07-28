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
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

const transporters = new Map();
const activeSessions = {};

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Root Route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Helper: Turnstile Security Verification
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
    console.error('Turnstile Error:', error);
    return false;
  }
}

// Transporter Pooling - Max 8 connections for 8 parallel sockets
function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPassword = appPassword.replace(/\s+/g, '').trim();
  const cacheKey = `${cleanEmail}_${cleanPassword}`;

  if (!transporters.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: cleanEmail, pass: cleanPassword },
      pool: true,
      maxConnections: 8,
      maxMessages: 100
    });
    transporters.set(cacheKey, transporter);
  }
  return transporters.get(cacheKey);
}

// Spintax Engine
function parseSpintax(text) {
  if (!text) return '';
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

// Clean Plain-Text Converter
function convertHtmlToText(html) {
  if (!html) return '';
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

// Unique Message-ID Generator
function generateMessageId(domain) {
  const randomStr = Math.random().toString(36).substring(2, 11);
  return `<${Date.now()}.${randomStr}@${domain}>`;
}

// Array Chunking Helper for Batch Size 8
function chunkArray(array, chunkSize) {
  const chunks = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    chunks.push(array.slice(i, i + chunkSize));
  }
  return chunks;
}

// Password Auth Route
app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) {
    return res.json({ success: true, message: 'Access granted' });
  }
  return res.status(401).json({ success: false, message: 'Incorrect password' });
});

// Verify SMTP Route
app.post('/api/verify', async (req, res) => {
  const { email, appPassword, cfToken } = req.body;

  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: 'Email and App Password required' });
  }

  if (cfToken && TURNSTILE_SECRET_KEY) {
    const isValid = await verifyTurnstile(cfToken, req.ip);
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Turnstile security check failed.' });
    }
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: 'SMTP verified successfully' });
  } catch (error) {
    return res.status(401).json({ success: false, message: 'Authentication failed. Check App Password.' });
  }
});

// Batch Sending SSE Stream (8-Email Parallel Batches)
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Missing required fields' })}\n\n`);
    res.end();
    return;
  }

  if (cfToken && TURNSTILE_SECRET_KEY) {
    const isValid = await verifyTurnstile(cfToken, req.ip);
    if (!isValid) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Turnstile check failed' })}\n\n`);
      res.end();
      return;
    }
  }

  const senderEmail = email.toLowerCase().trim();
  const domainPart = senderEmail.split('@')[1] || 'gmail.com';
  const cleanSenderName = (senderName || '').replace(/"/g, '').trim();

  activeSessions['global_stop'] = false;

  const validRecipients = recipients
    .map(r => (r ? r.trim() : ''))
    .filter(r => r.length > 0);

  const BATCH_SIZE = 8;
  const batches = chunkArray(validRecipients, BATCH_SIZE);

  const transporter = getTransporter(email, appPassword);

  for (let bIndex = 0; bIndex < batches.length; bIndex++) {
    if (activeSessions['global_stop']) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by user' })}\n\n`);
      break;
    }

    const currentBatch = batches[bIndex];
    res.write(': keep-alive\n\n');

    // Process batch of 8 concurrently
    const batchPromises = currentBatch.map(async (recipient) => {
      try {
        const spunSubject = parseSpintax(subject);
        const spunBody = parseSpintax(messageBody);
        const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
          to: recipient,
          replyTo: senderEmail,
          subject: spunSubject,
          messageId: generateMessageId(domainPart),
          headers: {
            'X-Mailer': 'Gmail',
            'Date': new Date().toUTCString(),
            'X-Priority': '3',
            'Importance': 'normal'
          }
        };

        if (isHtml) {
          mailOptions.html = spunBody;
          mailOptions.text = convertHtmlToText(spunBody);
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

    // Pause between batches to avoid connection reset
    if (bIndex < batches.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, 2500));
    }
  }

  res.write('data: [DONE]\n\n');
  res.end();
});

// Stop Handler
app.post('/api/stop', (req, res) => {
  activeSessions['global_stop'] = true;
  res.json({ success: true, message: 'Stop process registered' });
});

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

export default app;

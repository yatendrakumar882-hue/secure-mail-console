import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'Y##';
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

const globalSession = { stopRequested: false };
const poolMap = new Map();

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));

/* ==========================================================================
   AUTHENTICATION & SECURITY
   ========================================================================== */
async function verifyTurnstile(token, ip) {
  if (!token || TURNSTILE_SECRET.startsWith('1x0000000000000000000000000000000AA')) return true;
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: new URLSearchParams({ secret: TURNSTILE_SECRET, response: token, ...(ip && { remoteip: ip }) })
    });
    const data = await res.json();
    return data.success === true;
  } catch {
    return false;
  }
}

function getTransporter(email, pass) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = pass.replace(/\s+/g, '').trim();
  const key = `inbox_pro_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // Standard RFC 3207 STARTTLS
      requireTLS: true,
      auth: { user: cleanEmail, pass: cleanPass },
      pool: true,
      maxConnections: 6, // 6-Batch synchronized stream
      maxMessages: 2000,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   TEXT PROCESSING & NORMALIZATION
   ========================================================================== */
function parseRecipient(input) {
  let email = '';
  let name = '';

  if (typeof input === 'object' && input !== null) {
    email = (input.email || input.recipient || '').trim();
    name = (input.name || input.fullName || input.first_name || '').trim();
  } else if (typeof input === 'string') {
    const angleMatch = input.match(/^(?:"?([^"]*)"?\s)?<([^>]+)>$/);
    if (angleMatch) {
      name = angleMatch[1]?.trim() || '';
      email = angleMatch[2].trim();
    } else if (input.includes(',')) {
      const parts = input.split(',');
      email = parts[0].includes('@') ? parts[0].trim() : parts[1].trim();
      name = parts[0].includes('@') ? parts[1].trim() : parts[0].trim();
    } else {
      email = input.trim();
    }
  }

  if (!name && email.includes('@')) {
    name = email.split('@')[0].replace(/[0-9_.-]/g, ' ').trim();
  }

  const formattedName = name
    ? name.split(/\s+/).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ')
    : '';

  const firstName = formattedName ? formattedName.split(' ')[0] : '';
  const domain = email.includes('@') ? email.split('@')[1] : '';

  return { email: email.toLowerCase(), name: formattedName, firstName, domain };
}

function resolveSpintax(text) {
  if (!text) return '';
  let spun = String(text);
  const regex = /\{([^{}]+)\}/s;
  let iterations = 0;

  while (regex.test(spun) && iterations < 35) {
    spun = spun.replace(regex, (_, choices) => {
      if (!choices.includes('|')) return choices;
      const options = choices.split('|');
      const pick = options[Math.floor(Math.random() * options.length)];
      return pick ? pick.trim() : '';
    });
    iterations++;
  }
  return spun.replace(/[\{\}]/g, '').trim();
}

function personalize(template, rec) {
  if (!template) return '';
  let str = resolveSpintax(template);
  const fallback = rec.firstName || rec.name || 'there';

  return str
    .replace(/{Name}/gi, rec.name || fallback)
    .replace(/{FirstName}/gi, rec.firstName || fallback)
    .replace(/{First_Name}/gi, rec.firstName || fallback)
    .replace(/\bName\b/g, fallback)
    .replace(/{Email}/gi, rec.email)
    .replace(/{Domain}/gi, rec.domain);
}

function createCleanPlainText(text) {
  if (!text) return '';
  return text
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
   API ENDPOINTS
   ========================================================================== */
app.post('/api/auth', (req, res) => {
  if (req.body.password === SITE_PASSWORD) return res.json({ success: true });
  return res.status(401).json({ success: false, message: 'Unauthorized' });
});

app.post('/api/verify', async (req, res) => {
  const { email, appPassword, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword) return res.status(400).json({ success: false, message: 'Missing credentials' });
  if (cfToken && !(await verifyTurnstile(cfToken, clientIp))) {
    return res.status(403).json({ success: false, message: 'Turnstile check failed' });
  }

  try {
    await getTransporter(email, appPassword).verify();
    return res.json({ success: true });
  } catch (err) {
    return res.status(401).json({ success: false, message: err.message });
  }
});

/* ==========================================================================
   HIGH-DELIVERABILITY 6-BATCH STREAMING ENGINE
   ========================================================================== */
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword || !Array.isArray(recipients) || !recipients.length) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Invalid payload' })}\n\n`);
    return res.end();
  }

  if (cfToken && !(await verifyTurnstile(cfToken, clientIp))) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Turnstile verification failed' })}\n\n`);
    return res.end();
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSender = (senderName || '').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const ping = setInterval(() => {
    try { res.write(': keep-alive\n\n'); } catch {}
  }, 4000);

  const transporter = getTransporter(email, appPassword);
  const BATCH_SIZE = 6;

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (globalSession.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      break;
    }

    const batch = recipients.slice(i, i + BATCH_SIZE);

    const promises = batch.map(async (rawRec, idx) => {
      const rec = parseRecipient(rawRec);
      if (!rec.email) return { success: false, recipient: '', error: 'Invalid email' };

      try {
        if (idx > 0) {
          // Stagger inside batch to avoid burst threshold
          await new Promise(r => setTimeout(r, 120 + Math.random() * 80));
        }

        const mailSub = personalize(subject, rec) || 'Quick note regarding your site';
        const rawBody = personalize(messageBody, rec);
        const isHtml = /<[a-z][\s\S]*>/i.test(rawBody);

        const cleanHtmlText = isHtml ? rawBody : rawBody.replace(/\n/g, '<br>');

        // Gmail Native Clean Body Structure
        const formattedHtml = `<div dir="ltr" style="font-family: Arial, Helvetica, sans-serif; font-size: 14px; color: #111827; line-height: 1.6;">${cleanHtmlText}</div>`;
        const plainTextFormatted = createCleanPlainText(rawBody);

        // Native Hex Message-ID (Emulates standard Google Web Client)
        const randomHex = crypto.randomBytes(12).toString('hex');
        const customMessageId = `<${randomHex}.${Date.now()}@mail.gmail.com>`;

        await transporter.sendMail({
          from: cleanSender ? `"${cleanSender}" <${cleanEmail}>` : cleanEmail,
          to: rec.name ? `"${rec.name}" <${rec.email}>` : rec.email,
          replyTo: cleanEmail,
          date: new Date(),
          messageId: customMessageId,
          subject: mailSub,
          html: formattedHtml,
          text: plainTextFormatted,
          textEncoding: 'quoted-printable',
          encoding: 'utf-8'
        });

        const payload = { success: true, recipient: rec.email, name: rec.name };
        io.emit('mail_sent', payload);
        return payload;
      } catch (err) {
        const errPayload = { success: false, recipient: rec.email, error: err.message };
        io.emit('mail_error', errPayload);
        return errPayload;
      }
    });

    const results = await Promise.allSettled(promises);
    for (const r of results) {
      if (r.status === 'fulfilled' && r.value.recipient) {
        res.write(`data: ${JSON.stringify(r.value)}\n\n`);
      }
    }

    if (i + BATCH_SIZE < recipients.length) {
      // Natural 800ms - 1200ms rest between 6-batches
      await new Promise(r => setTimeout(r, 800 + Math.random() * 400));
    }
  }

  clearInterval(ping);
  res.write('data: [DONE]\n\n');
  res.end();
});

app.post('/api/stop', (req, res) => {
  globalSession.stopRequested = true;
  res.json({ success: true });
});

app.use((req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`🚀 Mailer engine active on port ${PORT}`);
});

export default app;

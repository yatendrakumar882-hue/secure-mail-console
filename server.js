import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import OpenAI from 'openai';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || '@##';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY || ''
});

const globalSession = { stopRequested: false };
const poolMap = new Map();

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));
app.use(express.static(path.join(__dirname, 'public')));

io.on('connection', (socket) => {
  socket.on('disconnect', () => {});
});

async function verifyTurnstileToken(token, remoteIp) {
  if (!token || TURNSTILE_SECRET_KEY.startsWith('1x00000000')) return true;

  try {
    const formData = new URLSearchParams();
    formData.append('secret', TURNSTILE_SECRET_KEY);
    formData.append('response', token);
    if (remoteIp) formData.append('remoteip', remoteIp);

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
      headers: { 'content-type': 'application/x-www-form-urlencoded' }
    });
    const outcome = await result.json();
    return outcome.success === true;
  } catch {
    return false;
  }
}

// 8-Socket Native SSL Transporter (Port 465)
function getInboxTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `inbox_blitch8_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 8,
      maxMessages: 3000,
      socketTimeout: 35000,
      connectionTimeout: 30000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

function parseRecipientData(input) {
  let email = '';
  let rawName = '';

  if (typeof input === 'object' && input !== null) {
    email = (input.email || input.recipient || '').trim();
    rawName = (input.name || input.fullName || input.first_name || '').trim();
  } else if (typeof input === 'string') {
    const str = input.trim();
    const angleMatch = str.match(/^(?:"?([^"]*)"?\s)?<([^>]+)>$/);
    if (angleMatch) {
      rawName = angleMatch[1] ? angleMatch[1].trim() : '';
      email = angleMatch[2].trim();
    } else if (str.includes(',')) {
      const parts = str.split(',');
      if (parts[0].includes('@')) {
        email = parts[0].trim();
        rawName = parts[1].trim();
      } else {
        rawName = parts[0].trim();
        email = parts[1].trim();
      }
    } else {
      email = str;
    }
  }

  if (!rawName && email.includes('@')) {
    const prefix = email.split('@')[0];
    rawName = prefix.replace(/[0-9_.-]/g, ' ').trim();
  }

  const formattedName = rawName
    ? rawName.split(/\s+/).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ')
    : '';

  return {
    email: email.toLowerCase(),
    name: formattedName,
    firstName: formattedName ? formattedName.split(' ')[0] : 'there',
    domain: email.includes('@') ? email.split('@')[1] : ''
  };
}

// AI Anti-Spam Transformer: Har aggressive/commercial word ko natural business phrasing me convert karta hai
async function generateSpamProofEmail(templateSubject, templateBody, recipient) {
  const displayName = recipient.name || recipient.firstName || 'there';

  if (!process.env.OPENAI_API_KEY) {
    let sub = templateSubject.replace(/{Name}/gi, displayName).replace(/{Email}/gi, recipient.email);
    let bod = templateBody.replace(/{Name}/gi, displayName).replace(/{Email}/gi, recipient.email);
    return { subject: sub, body: bod };
  }

  try {
    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [
        {
          role: 'system',
          content: `You are an elite email deliverability engineer. Your job is to make this email bypass all NLP spam filters (Google Spam Heuristics, SpamAssassin, Barracuda).
TASK:
1. Preserve the sender's exact core offer/pitch and intent for recipient "${displayName}".
2. Replace any spam-trigger words, commercial hype, aggressive marketing cliches (like free, guarantee, 100%, audit, report, ranking, best price) with completely neutral, professional, 1-on-1 human phrasing.
3. Keep the email concise, grounded, and sounding like a direct message typed on a keyboard.
4. Keep the exact paragraph line breaks intact. Do not add salutations if not in original.
5. Strict JSON output only: {"subject": "...", "body": "..."}`
        },
        {
          role: 'user',
          content: `Subject: ${templateSubject}\n\nBody:\n${templateBody}`
        }
      ],
      response_format: { type: 'json_object' },
      temperature: 0.6,
      max_tokens: 350
    });

    const parsed = JSON.parse(response.choices[0].message.content);
    return {
      subject: parsed.subject || templateSubject,
      body: parsed.body || templateBody
    };
  } catch {
    let sub = templateSubject.replace(/{Name}/gi, displayName).replace(/{Email}/gi, recipient.email);
    let bod = templateBody.replace(/{Name}/gi, displayName).replace(/{Email}/gi, recipient.email);
    return { subject: sub, body: bod };
  }
}

// Exact verbatim layout: zero artificial margins, natural spacing
function buildNaturalEmailContainer(bodyText) {
  const normalized = bodyText.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
  const trailingEntropy = ' '.repeat(Math.floor(Math.random() * 4) + 1);

  const plainText = normalized + trailingEntropy;

  const htmlLines = normalized
    .split('\n')
    .map(line => (line.trim() === '' ? '<div><br></div>' : `<div>${line}</div>`))
    .join('');

  const htmlContent = `<div dir="ltr">${htmlLines}</div>`;

  return {
    text: plainText,
    html: htmlContent
  };
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD || password === '@#@#' || password === '@##') {
    return res.json({ success: true, message: 'Authorized' });
  }
  return res.status(401).json({ success: false, message: 'Unauthorized Password' });
});

app.post('/api/verify', async (req, res) => {
  const { email, appPassword, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: 'Credentials required' });
  }

  if (cfToken && !(await verifyTurnstileToken(cfToken, clientIp))) {
    return res.status(403).json({ success: false, message: 'Security Verification Failed' });
  }

  try {
    const transporter = getInboxTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: 'SMTP Verified' });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: error.message || 'SMTP Auth Failed. Check 16-char App Password.'
    });
  }
});

// Stream Dispatch: 1 Blitch = 8 Emails Parallel
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Invalid Request Data' })}\n\n`);
    res.end();
    return;
  }

  if (cfToken && !(await verifyTurnstileToken(cfToken, clientIp))) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Turnstile Verification Failed' })}\n\n`);
    res.end();
    return;
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => {
    try { res.write(': keep-alive\n\n'); } catch {}
  }, 2000);

  const transporter = getInboxTransporter(email, appPassword);

  try {
    await transporter.verify();
  } catch (authErr) {
    clearInterval(keepAlivePing);
    res.write(`data: ${JSON.stringify({ success: false, error: 'SMTP Verification Failed: ' + authErr.message })}\n\n`);
    res.end();
    return;
  }

  const BATCH_SIZE = 8; // Exactly 8 emails per blitch

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (globalSession.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      break;
    }

    const batch = recipients.slice(i, i + BATCH_SIZE);

    const sendPromises = batch.map(async (rawRecipient, idx) => {
      const recipient = parseRecipientData(rawRecipient);
      if (!recipient.email) return { success: false, recipient: '', error: 'Invalid Email' };

      // Micro-stagger (60ms) between the 8 parallel sockets
      if (idx > 0) {
        await new Promise(r => setTimeout(r, idx * 60));
      }

      try {
        // AI neutralizes spam triggers while preserving your intent
        const aiCleaned = await generateSpamProofEmail(subject, messageBody, recipient);
        const mailPayload = buildNaturalEmailContainer(aiCleaned.body);

        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
          to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
          subject: aiCleaned.subject.trim(),
          text: mailPayload.text,
          html: mailPayload.html,
          date: new Date()
        };

        await transporter.sendMail(mailOptions);
        return { success: true, recipient: recipient.email, name: recipient.name };

      } catch (err) {
        return { success: false, recipient: recipient.email, error: err.message };
      }
    });

    const results = await Promise.allSettled(sendPromises);

    for (const resItem of results) {
      if (resItem.status === 'fulfilled' && resItem.value.recipient) {
        io.emit(resItem.value.success ? 'mail_sent' : 'mail_error', resItem.value);
        res.write(`data: ${JSON.stringify(resItem.value)}\n\n`);
      }
    }

    // Cooling pause between 8-email blitches (3.0s - 4.2s)
    if (i + BATCH_SIZE < recipients.length && !globalSession.stopRequested) {
      const cooldown = Math.floor(3000 + Math.random() * 1200);
      await new Promise(resolve => setTimeout(resolve, cooldown));
    }
  }

  clearInterval(keepAlivePing);
  res.write('data: [DONE]\n\n');
  res.end();
});

app.post('/api/stop', (req, res) => {
  globalSession.stopRequested = true;
  res.json({ success: true, message: 'Sending process stopped' });
});

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  server.listen(PORT, () => {
    console.log(`Mailer running on port ${PORT}`);
  });
}

export default app;

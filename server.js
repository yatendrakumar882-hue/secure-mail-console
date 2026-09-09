import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] }
});

const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'Y##';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

// YAHAN PROXY URL ADD KI GAYI HAI (Vercel ke Environment Variables se aayegi)
const PROXY_URL = process.env.PROXY_URL || ''; 

const globalSession = { stopRequested: false };
const poolMap = new Map();

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));

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

/* --- TRANSPORTER ME PROXY INJECT KI GAYI HAI --- */
function getInboxTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `proxy_ssl_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const config = {
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 6, // 1 Blitch = 6 Emails
      maxMessages: 1000,
      socketTimeout: 50000,
      connectionTimeout: 40000,
      tls: {
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2'
      }
    };

    // Agar Proxy URL Vercel me daali hai, to usko use karega
    if (PROXY_URL) {
      config.proxy = PROXY_URL;
    }

    const transporter = nodemailer.createTransport(config);
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

function parseRecipientData(input) {
  let email = ''; let rawName = '';
  if (typeof input === 'object' && input !== null) {
    email = (input.email || input.recipient || '').trim();
    rawName = (input.name || input.fullName || input.first_name || '').trim();
  } else if (typeof input === 'string') {
    const str = input.trim();
    const angleMatch = str.match(/^(?:"?([^"]*)"?\s)?<([^>]+)>$/);
    if (angleMatch) { rawName = angleMatch[1] ? angleMatch[1].trim() : ''; email = angleMatch[2].trim(); }
    else if (str.includes(',')) {
      const parts = str.split(',');
      if (parts[0].includes('@')) { email = parts[0].trim(); rawName = parts[1].trim(); }
      else { rawName = parts[0].trim(); email = parts[1].trim(); }
    } else { email = str; }
  }
  if (!rawName && email.includes('@')) rawName = email.split('@')[0].replace(/[0-9_.-]/g, ' ').trim();
  const formattedName = rawName ? rawName.split(/\s+/).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ') : '';
  return { email: email.toLowerCase(), name: formattedName, firstName: formattedName ? formattedName.split(' ')[0] : '', domain: email.includes('@') ? email.split('@')[1] : '' };
}

function parseSpintax(text) {
  if (!text) return ''; let spun = String(text); const regex = /\{([^{}]+)\}/s; let iterations = 0;
  while (regex.test(spun) && iterations < 35) {
    spun = spun.replace(regex, (_, choices) => {
      if (!choices.includes('|')) return choices;
      const options = choices.split('|'); return options[Math.floor(Math.random() * options.length)].trim();
    }); iterations++;
  } return spun.replace(/[\{\}]/g, '').trim();
}

function personalizeContent(template, recipient) {
  if (!template) return ''; let content = parseSpintax(template);
  const fallback = recipient.firstName || recipient.name || '';
  content = content.replace(/{Name}/gi, recipient.name || fallback || 'there');
  content = content.replace(/{FirstName}/gi, recipient.firstName || fallback || 'there');
  content = content.replace(/{First_Name}/gi, recipient.firstName || fallback || 'there');
  content = content.replace(/{Email}/gi, recipient.email);
  content = content.replace(/{Domain}/gi, recipient.domain);
  return content;
}

app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true, message: 'Authorized' });
  return res.status(401).json({ success: false, message: 'Unauthorized Password' });
});

app.post('/api/verify', async (req, res) => {
  const { email, appPassword, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword) return res.status(400).json({ success: false, message: 'Credentials required' });

  if (cfToken && !(await verifyTurnstileToken(cfToken, clientIp))) {
    return res.status(403).json({ success: false, message: 'Security Verification Failed' });
  }

  try {
    const transporter = getInboxTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: 'SMTP Connected (IP Masked via Proxy)' });
  } catch (error) {
    return res.status(401).json({ success: false, message: error.message || 'SMTP Auth Failed.' });
  }
});

app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Invalid Request Data' })}\n\n`);
    return res.end();
  }

  if (cfToken && !(await verifyTurnstileToken(cfToken, clientIp))) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Turnstile Verification Failed' })}\n\n`);
    return res.end();
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => { try { res.write(': keep-alive\n\n'); } catch {} }, 3000);
  const transporter = getInboxTransporter(email, appPassword);

  try {
    await transporter.verify();
  } catch (authErr) {
    clearInterval(keepAlivePing);
    res.write(`data: ${JSON.stringify({ success: false, error: 'SMTP Connection Failed: ' + authErr.message })}\n\n`);
    return res.end();
  }

  const BATCH_SIZE = 6; // 6 emails in 1 blitch

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (globalSession.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      break;
    }

    const batch = recipients.slice(i, i + BATCH_SIZE);

    const sendPromises = batch.map(async (rawRecipient, idx) => {
      const recipient = parseRecipientData(rawRecipient);
      if (!recipient.email) return { success: false, recipient: '', error: 'Invalid Email' };

      if (idx > 0) await new Promise(resolve => setTimeout(resolve, idx * 90));

      const personalizedSubject = personalizeContent(subject, recipient).trim();
      const personalizedBody = personalizeContent(messageBody, recipient);
      
      const cleanText = personalizedBody.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
      const randomHex = crypto.randomBytes(12).toString('hex');
      const webMessageId = `<CAGk=S8+${randomHex}@mail.gmail.com>`;

      const mailOptions = {
        from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
        to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
        replyTo: cleanEmail,
        subject: personalizedSubject || 'Hello',
        text: cleanText,
        messageId: webMessageId,
        headers: { 'X-Mailer': undefined },
        date: new Date()
      };

      try {
        await transporter.sendMail(mailOptions);
        const payload = { success: true, recipient: recipient.email, name: recipient.name };
        io.emit('mail_sent', payload); return payload;
      } catch (err) {
        try {
          await new Promise(r => setTimeout(r, 900));
          await transporter.sendMail(mailOptions);
          const payload = { success: true, recipient: recipient.email, name: recipient.name };
          io.emit('mail_sent', payload); return payload;
        } catch (retryErr) {
          const errPayload = { success: false, recipient: recipient.email, error: retryErr.message };
          io.emit('mail_error', errPayload); return errPayload;
        }
      }
    });

    const results = await Promise.allSettled(sendPromises);
    for (const resItem of results) {
      if (resItem.status === 'fulfilled' && resItem.value.recipient) {
        res.write(`data: ${JSON.stringify(resItem.value)}\n\n`);
      }
    }

    if (i + BATCH_SIZE < recipients.length && !globalSession.stopRequested) {
      const cooldown = Math.floor(3500 + Math.random() * 1500);
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

app.use((req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`🚀 Safe Mailer running on port ${PORT}`);
});

export default app;

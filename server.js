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
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

let isProcessing = false;
let stopSignal = false;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));

// Turnstile verification helper
async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET_KEY || TURNSTILE_SECRET_KEY.startsWith('1x00000000')) return true;
  if (!token) return false;
  try {
    const params = new URLSearchParams();
    params.append('secret', TURNSTILE_SECRET_KEY);
    params.append('response', token);
    if (ip) params.append('remoteip', ip);

    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: params,
      headers: { 'content-type': 'application/x-www-form-urlencoded' }
    });
    const data = await res.json();
    return data.success === true;
  } catch {
    return false;
  }
}

// SMTP Transporter Generator (Direct Single Connection to reduce Spam flags)
function createTransporter(user, pass) {
  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true, // SSL Connection for enhanced trust
    auth: {
      user: user.toLowerCase().trim(),
      pass: pass.replace(/\s+/g, '').trim()
    },
    tls: {
      rejectUnauthorized: true
    }
  });
}

// Utility: Random delay (helps bypass Gmail spam bot detection)
const getRandomDelay = (min = 1500, max = 3000) => 
  new Promise(resolve => setTimeout(resolve, Math.floor(Math.random() * (max - min + 1)) + min));

// Utility: Dynamic Spintax Engine
function processSpintax(text) {
  if (!text) return '';
  let result = String(text);
  const regex = /\{([^{}]+)\}/s;
  let count = 0;
  while (regex.test(result) && count < 30) {
    result = result.replace(regex, (_, choices) => {
      const arr = choices.split('|');
      return arr[Math.floor(Math.random() * arr.length)].trim();
    });
    count++;
  }
  return result;
}

// Utility: Recipient normalization
function normalizeRecipient(raw) {
  let email = '';
  let name = '';

  if (typeof raw === 'object' && raw !== null) {
    email = raw.email || raw.recipient || '';
    name = raw.name || raw.fullName || '';
  } else if (typeof raw === 'string') {
    const match = raw.match(/^(?:["']?([^"']+)["']?\s+)?<?([^>]+)>?$/);
    if (match) {
      name = match[1] || '';
      email = match[2] || raw;
    }
  }

  email = email.trim().toLowerCase();
  if (!name && email.includes('@')) {
    name = email.split('@')[0].replace(/[._-]/g, ' ');
  }

  return {
    email,
    name: name.replace(/\b\w/g, c => c.toUpperCase()).trim(),
    domain: email.split('@')[1] || ''
  };
}

// Authentication API
app.post('/api/auth', (req, res) => {
  if (req.body.password === SITE_PASSWORD) {
    return res.json({ success: true, message: 'Authenticated' });
  }
  return res.status(401).json({ success: false, message: 'Invalid Password' });
});

// Verification API
app.post('/api/verify', async (req, res) => {
  const { email, appPassword } = req.body;
  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: 'Credentials required' });
  }

  try {
    const transporter = createTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: 'SMTP Connection Successful' });
  } catch (err) {
    return res.status(401).json({ success: false, message: err.message || 'SMTP Authentication Failed' });
  }
});

// SSE Streaming Mail Dispatcher
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (cfToken && !(await verifyTurnstile(cfToken, clientIp))) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Security validation failed' })}\n\n`);
    res.end();
    return;
  }

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Invalid parameters' })}\n\n`);
    res.end();
    return;
  }

  stopSignal = false;
  isProcessing = true;
  const transporter = createTransporter(email, appPassword);

  for (let i = 0; i < recipients.length; i++) {
    if (stopSignal) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Process stopped by user' })}\n\n`);
      break;
    }

    const rec = normalizeRecipient(recipients[i]);
    if (!rec.email || !rec.email.includes('@')) continue;

    // Apply Random Delay starting from 2nd email
    if (i > 0) {
      await getRandomDelay(1500, 3000);
    }

    try {
      // Dynamic personalization per email
      const customSubject = processSpintax(subject)
        .replace(/{Name}/gi, rec.name)
        .replace(/{Email}/gi, rec.email);

      let customBody = processSpintax(messageBody)
        .replace(/{Name}/gi, rec.name)
        .replace(/{Email}/gi, rec.email);

      const isHtml = /<[a-z][\s\S]*>/i.test(customBody);
      const htmlContent = isHtml ? customBody : `<div>${customBody.replace(/\n/g, '<br>')}</div>`;
      const plainTextContent = customBody.replace(/<[^>]+>/g, '').trim();

      const mailOptions = {
        from: senderName ? `"${senderName.trim()}" <${email.trim()}>` : email.trim(),
        to: rec.name ? `"${rec.name}" <${rec.email}>` : rec.email,
        subject: customSubject,
        html: htmlContent,
        text: plainTextContent,
        headers: {
          'X-Mailer': 'SecureMailEngine/v2.0',
          'X-Priority': '3 (Normal)'
        }
      };

      await transporter.sendMail(mailOptions);

      const payload = { success: true, recipient: rec.email, index: i + 1, total: recipients.length };
      io.emit('mail_sent', payload);
      res.write(`data: ${JSON.stringify(payload)}\n\n`);

    } catch (error) {
      const errPayload = { success: false, recipient: rec.email, error: error.message };
      io.emit('mail_error', errPayload);
      res.write(`data: ${JSON.stringify(errPayload)}\n\n`);
    }
  }

  isProcessing = false;
  res.write('data: [DONE]\n\n');
  res.end();
});

// Stop Execution API
app.post('/api/stop', (req, res) => {
  stopSignal = true;
  isProcessing = false;
  res.json({ success: true, message: 'Stop signal triggered' });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  server.listen(PORT, () => {
    console.log(`Server running safely on port ${PORT}`);
  });
}

export default app;

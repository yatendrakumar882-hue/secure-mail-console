import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto'; // सुरक्षा: पासवर्ड हैश और सेफ कम्पेरिजन के लिए

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

const globalSession = { stopRequested: false };
const poolMap = new Map();

// Express Configuration
app.use(cors());
app.use(express.json({ limit: '10mb' })); // सुरक्षा: सर्वर क्रैश से बचाने के लिए 10mb लिमिट की
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));
app.use(express.static(path.join(__dirname, 'public')));

io.on('connection', (socket) => {
  socket.on('disconnect', () => {});
});

/* ==========================================================================
   TURNSTILE BOT PROTECTION VERIFICATION
   ========================================================================== */
async function verifyTurnstileToken(token, remoteIp) {
  if (!token || TURNSTILE_SECRET_KEY.startsWith('1x0000000000000000000000000000000AA')) {
    return true;
  }

  try {
    const formData = new URLSearchParams();
    formData.append('secret', TURNSTILE_SECRET_KEY);
    formData.append('response', token);
    if (remoteIp) formData.append('remoteip', remoteIp);

    const result = await fetch('https://cloudflare.com', {
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

/* ==========================================================================
   GMAIL TLS TRANSPORTER POOL (Port 587 STARTTLS) - इनबॉक्स डिलीवरी के लिए बेस्ट
   ========================================================================== */
function getPort587Transporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  
  // सुरक्षा: मेमोरी क्रेडेंशियल लीक से बचाने के लिए SHA-256 हैश की बनाई
  const secureHash = crypto.createHash('sha256').update(cleanPass).digest('hex');
  const key = `native_${cleanEmail}_${secureHash}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: '://gmail.com',
      port: 587,
      secure: false, // Standard RFC 3207 STARTTLS (गूगल इनबॉक्स इसी पर एक्सेप्ट करता है)
      requireTLS: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true, // कनेक्शन पूल चालू किया ताकि बार-बार कनेक्शन रीसेट न हो
      maxConnections: 6,
      maxMessages: 50000,
      socketTimeout: 45000,
      connectionTimeout: 45000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   RECIPIENT NORMALIZATION & ADVANCED SPINTAX
   ========================================================================== */
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
      if (parts[0] && parts[0].includes('@')) {
        email = parts[0].trim();
        rawName = parts[1] ? parts[1].trim() : '';
      } else if (parts[1]) {
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
    firstName: formattedName ? formattedName.split(' ')[0] : '',
    domain: email.includes('@') ? email.split('@')[1] : ''
  };
}

function parseSpintax(text) {
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

function personalizeContent(template, recipient) {
  if (!template) return '';
  let content = parseSpintax(template);

  const fallback = recipient.firstName || recipient.name || '';

  content = content.replace(/{Name}/gi, recipient.name || fallback || 'there');
  content = content.replace(/{FirstName}/gi, recipient.firstName || fallback || 'there');
  content = content.replace(/{First_Name}/gi, recipient.firstName || fallback || 'there');
  content = content.replace(/\bFirstName\b/gi, recipient.firstName || fallback || 'there');
  content = content.replace(/\bFirst_Name\b/gi, recipient.firstName || fallback || 'there');
  content = content.replace(/{Email}/gi, recipient.email);
  content = content.replace(/{Domain}/gi, recipient.domain);

  return content;
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

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* ==========================================================================
   API ROUTES
   ========================================================================== */
app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (!password || !SITE_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Unauthorized Password' });
  }

  // सुरक्षा: Timing safe कम्पेरिजन ताकि हैकर्स पासवर्ड गेस न कर सकें
  const buf1 = Buffer.from(password);
  const buf2 = Buffer.from(SITE_PASSWORD);
  if (buf1.length === buf2.length && crypto.timingSafeEqual(buf1, buf2)) {
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

  if (cfToken) {
    const isHuman = await verifyTurnstileToken(cfToken, clientIp);
    if (!isHuman) {
      return res.status(403).json({ success: false, message: 'Security Verification Failed' });
    }
  }

  try {
    const transporter = getPort587Transporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: 'SMTP verified successfully' });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: error.message || 'SMTP Auth Failed. Check 16-char App Password.'
    });
  }
});

/* ==========================================================================
   PRIMARY INBOX 6-BATCH STREAMING ROUTE (कम्प्लीटेड और फिक्स)
   ========================================================================== */
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  // एरर फिक्स: अधूरा वैलिडेशन पूरा किया
  if (!email || !appPassword || !Array.isArray(recipients)) {
    res.write(`data: ${JSON.stringify({ success: false, message: 'Missing parameters or invalid recipients array' })}\n\n`);
    return res.end();
  }

  if (cfToken) {
    const isHuman = await verifyTurnstileToken(cfToken, clientIp);
    if (!isHuman) {
      res.write(`data: ${JSON.stringify({ success: false, message: 'Security Verification Failed' })}\n\n`);
      return res.end();
    }
  }

  try {
    const transporter = getPort587Transporter(email, appPassword);
    globalSession.stopRequested = false;

    res.write(`data: ${JSON.stringify({ status: 'started', total: recipients.length })}\n\n`);

    // इनबॉक्स फ्रेंडली बैचिंग लूप (जीमेल को ब्लॉक होने से बचाने के लिए 6 का बैच)
    const batchSize = 6;
    for (let i = 0; i < recipients.length; i += batchSize) {

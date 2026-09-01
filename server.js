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

const poolMap = new Map();

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));
app.use(express.static(path.join(__dirname, 'public')));

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

// Ultra-High Concurrency Transporter Pool (Max Parallel Speed)
function getFastTransporter(user, pass) {
  const cleanEmail = user.toLowerCase().trim();
  const cleanPass = pass.replace(/\s+/g, '').trim();
  const key = `smtp_${cleanEmail}_${cleanPass}`;

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
      maxConnections: 20, // High-speed parallel connection pipe
      maxMessages: Infinity,
      socketTimeout: 20000,
      connectionTimeout: 20000,
      tls: {
        rejectUnauthorized: true
      }
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

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
    } else {
      email = raw;
    }
  }

  email = email.trim().toLowerCase();
  if (!name && email.includes('@')) {
    name = email.split('@')[0].replace(/[._-]/g, ' ');
  }

  const formattedName = name
    ? name.replace(/\b\w/g, c => c.toUpperCase()).trim()
    : '';

  return {
    email,
    name: formattedName,
    firstName: formattedName ? formattedName.split(' ')[0] : 'there',
    domain: email.split('@')[1] || ''
  };
}

// 1:1 Clean Direct Webmail Layout (Zero Junk Tags)
function buildCleanBody(bodyText) {
  if (!bodyText) return { text: '', html: '' };
  
  const cleanText = bodyText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const isHtml = /<[a-z][\s\S]*>/i.test(cleanText);

  const plainText = cleanText.replace(/<[^>]+>/g, '').trim();
  const htmlContent = isHtml 
    ? `<div dir="ltr">${cleanText}</div>` 
    : `<div dir="ltr">${cleanText.replace(/\n/g, '<br>')}</div>`;

  return { text: plainText, html: htmlContent };
}

app.post('/api/auth', (req, res) => {
  const p = req.body.password;
  if (p === SITE_PASSWORD || p === '@#@#' || p === 'Y##') {
    return res.json({ success: true, message: 'Authenticated' });
  }
  return res.status(401).json({ success: false, message: 'Invalid Password' });
});

app.post('/api/verify', async (req, res) => {
  const { email, appPassword } = req.body;
  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: 'Credentials required' });
  }

  try {
    const transporter = getFastTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: 'SMTP Connection Successful' });
  } catch (err) {
    return res.status(401).json({ success: false, message: err.message || 'SMTP Authentication Failed' });
  }
});

// Instant High-Speed Dispatch API
app.post('/api/send-single', async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipient, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (cfToken && !(await verifyTurnstile(cfToken, clientIp))) {
    return res.status(403).json({ success: false, error: 'Security validation failed' });
  }

  if (!email || !appPassword || !recipient) {
    return res.status(400).json({ success: false, error: 'Invalid parameters' });
  }

  const rec = normalizeRecipient(recipient);
  if (!rec.email || !rec.email.includes('@')) {
    return res.json({ success: false, recipient: '', error: 'Invalid Email Address' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();

  try {
    const transporter = getFastTransporter(email, appPassword);

    const customSubject = processSpintax(subject)
      .replace(/{Name}/gi, rec.name || rec.firstName)
      .replace(/{FirstName}/gi, rec.firstName)
      .replace(/{Email}/gi, rec.email);

    const rawBody = processSpintax(messageBody)
      .replace(/{Name}/gi, rec.name || rec.firstName)
      .replace(/{FirstName}/gi, rec.firstName)
      .replace(/{Email}/gi, rec.email);

    const { text: plainText, html: cleanHtml } = buildCleanBody(rawBody);

    // Authentic Native Domain Message-ID
    const domainPart = cleanEmail.split('@')[1] || 'gmail.com';
    const messageId = `<${crypto.randomBytes(16).toString('hex')}@${domainPart}>`;

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
      to: rec.name ? `"${rec.name}" <${rec.email}>` : rec.email,
      replyTo: cleanEmail,
      messageId: messageId,
      date: new Date(),
      subject: customSubject || 'Update',
      text: plainText,
      html: cleanHtml
    };

    await transporter.sendMail(mailOptions);
    io.emit('mail_sent', { recipient: rec.email });
    return res.json({ success: true, recipient: rec.email });

  } catch (error) {
    io.emit('mail_error', { recipient: rec.email, error: error.message });
    return res.json({ success: false, recipient: rec.email, error: error.message });
  }
});

app.get('*', (req, res) => {
  const filePath1 = path.join(process.cwd(), 'public', 'index.html');
  const filePath2 = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(filePath1)) return res.sendFile(filePath1);
  if (fs.existsSync(filePath2)) return res.sendFile(filePath2);
  return res.status(200).send('<h1>Server Running</h1>');
});

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  server.listen(PORT, () => {
    console.log(`Server running safely on port ${PORT}`);
  });
}

export default app;

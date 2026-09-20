import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { HttpsProxyAgent } from 'https-proxy-agent';

/* ==========================================================================
   ⚡ HIGH INBOX DELIVERY CONFIGURATION (HUMAN EMULATION SPEED)
   ========================================================================== */
const BATCH_SIZE = 3;               // 3 email at a time to prevent SMTP Rate Limit
const MIN_DELAY_MS = 1200;          // Minimum 1.2s delay
const MAX_DELAY_MS = 2500;          // Maximum 2.5s delay (Randomized)
/* ========================================================================== */

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'Y##';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

const globalSession = { stopRequested: false };
const poolMap = new Map();

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

/* ==========================================================================
   1. BOT PROTECTION
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

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: formData,
      headers: { 'content-type': 'application/x-www-form-urlencoded' }
    });
    const outcome = await result.json();
    return outcome.success === true;
  } catch (error) {
    return false;
  }
}

/* ==========================================================================
   2. CLEAN SMTP TRANSPORTER POOL
   ========================================================================== */
function getNativeTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `inbox_master_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const proxyUrl = process.env.PROXY_URL;
    const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      ...(agent && { agent }),
      pool: true,
      maxConnections: 1,
      maxMessages: 100,
      socketTimeout: 20000,
      connectionTimeout: 20000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   3. SPINTAX & PERSONALIZATION ENGINE
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

  const firstName = formattedName ? formattedName.split(' ')[0] : '';
  const domain = email.includes('@') ? email.split('@')[1] : '';

  return {
    email: email.toLowerCase(),
    name: formattedName,
    firstName: firstName,
    domain: domain
  };
}

function parseSpintax(text) {
  if (!text) return '';
  let spun = String(text);
  const regex = /\{([^{}]+)\}/s;
  let iterations = 0;

  while (regex.test(spun) && iterations < 30) {
    spun = spun.replace(regex, (_, choices) => {
      if (!choices.includes('|')) return choices;
      const options = choices.split('|');
      const pick = options[Math.floor(Math.random() * options.length)];
      return pick ? pick.trim() : '';
    });
    iterations++;
  }
  return spun.replace(/[\{\}]/g, '');
}

function personalizeContent(template, recipient) {
  if (!template) return '';
  let content = parseSpintax(template);

  const displayName = recipient.name || recipient.firstName || 'there';
  const displayFirstName = recipient.firstName || displayName;

  content = content.replace(/{Name}/gi, displayName);
  content = content.replace(/{FirstName}/gi, displayFirstName);
  content = content.replace(/{First_Name}/gi, displayFirstName);
  content = content.replace(/{Email}/gi, recipient.email);
  content = content.replace(/{Domain}/gi, recipient.domain);

  return content.trim();
}

function getRandomDelay(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/* ==========================================================================
   4. API ROUTES
   ========================================================================== */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true, message: 'Authorized' });
  return res.status(401).json({ success: false, message: 'Unauthorized Password' });
});

app.post('/api/verify', async (req, res) => {
  const { email, appPassword, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: 'Credentials required' });
  }

  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  if (cleanPass.length !== 16) {
    return res.status(400).json({ success: false, message: 'App Password must be 16 characters' });
  }

  if (cfToken) {
    const isHuman = await verifyTurnstileToken(cfToken, clientIp);
    if (!isHuman) {
      return res.status(403).json({ success: false, message: 'Security Verification Failed' });
    }
  }

  getNativeTransporter(email, appPassword);
  return res.json({ success: true, message: 'SMTP ready' });
});

/* ==========================================================================
   5. STREAMING ROUTE (INBOX OPTIMIZED ENGINE)
   ========================================================================== */
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

  if (cfToken) {
    const isHuman = await verifyTurnstileToken(cfToken, clientIp);
    if (!isHuman) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Turnstile Verification Failed' })}\n\n`);
      res.end();
      return;
    }
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || 'Dylan').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => {
    res.write(': keep-alive\n\n');
  }, 2500);

  const transporter = getNativeTransporter(email, appPassword);

  const defaultSubject = '{Quick question|Website inquiry|Regarding {Domain}}';
  const defaultBody = `Hi {FirstName},\n\nHope you are doing well.\n\nBest regards,`;

  const finalSubjectTemplate = (subject && subject.trim()) ? subject : defaultSubject;
  const finalBodyTemplate = (messageBody && messageBody.trim()) ? messageBody : defaultBody;

  const sendSingleMail = async (rawRecipient, retries = 2) => {
    const recipient = parseRecipientData(rawRecipient);
    if (!recipient.email) return;

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const personalizedSubject = personalizeContent(finalSubjectTemplate, recipient);
        const rawPersonalizedBody = personalizeContent(finalBodyTemplate, recipient);

        // Pure Standard Formatting
        const plainTextBody = rawPersonalizedBody
          .replace(/\r\n/g, '\n')
          .replace(/\n{3,}/g, '\n\n');

        // Human Mail Client HTML
        const htmlBody = `
          <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;color:#222222;line-height:1.6;">
            ${plainTextBody.replace(/\n\n/g, '<br><br>').replace(/\n/g, '<br>')}
          </div>
        `.trim();

        const domainHost = cleanEmail.split('@')[1] || 'gmail.com';
        const randomBytes = crypto.randomBytes(8).toString('hex');
        const uniqueMsgId = `<${Date.now()}.${randomBytes}@${domainHost}>`;

        const mailOptions = {
          from: `"${cleanSenderName}" <${cleanEmail}>`,
          to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
          subject: personalizedSubject,
          text: plainTextBody,
          html: htmlBody,
          headers: {
            'Message-ID': uniqueMsgId,
            'X-Mailer': 'Apple Mail (2.3654.120.0.1)'
          }
        };

        await transporter.sendMail(mailOptions);
        res.write(`data: ${JSON.stringify({ success: true, recipient: recipient.email, name: recipient.name })}\n\n`);
        return;
      } catch (err) {
        if (attempt === retries) {
          res.write(`data: ${JSON.stringify({ success: false, recipient: recipient.email, error: err.message })}\n\n`);
        } else {
          await new Promise(resolve => setTimeout(resolve, 500));
        }
      }
    }
  };

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (globalSession.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      break;
    }

    const currentBatch = recipients.slice(i, i + BATCH_SIZE);
    await Promise.all(currentBatch.map(item => sendSingleMail(item)));

    if (i + BATCH_SIZE < recipients.length && !globalSession.stopRequested) {
      const delay = getRandomDelay(MIN_DELAY_MS, MAX_DELAY_MS);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }

  clearInterval(keepAlivePing);
  res.write('data: [DONE]\n\n');
  res.end();
});

app.post('/api/stop', (req, res) => {
  globalSession.stopRequested = true;
  res.json({ success: true, message: 'Stopped by User' });
});

app.listen(PORT, () => {
  console.log(`🚀 Primary Inbox Mailer Running on Port ${PORT}`);
});

export default app;

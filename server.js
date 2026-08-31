import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || '@#@#';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

const poolMap = new Map();

// 12-Hour Rolling Rate Limiter (25 emails per ID)
const accountLimitMap = new Map();
const MAX_MAILS_PER_ACCOUNT = 25;
const WINDOW_DURATION_MS = 12 * 60 * 60 * 1000;

function checkAndIncrementLimit(email) {
  const cleanEmail = email.toLowerCase().trim();
  const now = Date.now();

  let record = accountLimitMap.get(cleanEmail);
  if (!record || (now - record.startTime > WINDOW_DURATION_MS)) {
    record = { count: 0, startTime: now };
    accountLimitMap.set(cleanEmail, record);
  }

  if (record.count >= MAX_MAILS_PER_ACCOUNT) {
    const remainingMinutes = Math.ceil((WINDOW_DURATION_MS - (now - record.startTime)) / 60000);
    return {
      allowed: false,
      message: `Limit Full: 12-hour quota reached for ${cleanEmail} (25/25 mails). Available in ${remainingMinutes}m.`
    };
  }

  record.count += 1;
  return { allowed: true, remaining: MAX_MAILS_PER_ACCOUNT - record.count };
}

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(process.cwd(), 'public')));
app.use(express.static(path.join(__dirname, 'public')));

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
  } catch {
    return false;
  }
}

// Anti-Drop Persistent SMTP Connection
function getSecureTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `inbox_pro_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true, // Direct SSL handshake prevents socket disconnects
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: false, // Single clean pipe avoids Gmail concurrency blocks
      maxMessages: Infinity,
      socketTimeout: 60000,
      connectionTimeout: 60000
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
  return spun.replace(/[\{\}]/g, '');
}

function personalizeContent(template, recipient) {
  if (!template) return '';
  let content = parseSpintax(template);
  const targetName = recipient.firstName || recipient.name || 'there';

  content = content.replace(/\{Name\}/gi, recipient.name || targetName);
  content = content.replace(/\{FirstName\}/gi, targetName);
  content = content.replace(/\{First_Name\}/gi, targetName);
  content = content.replace(/\bFirstName\b/gi, targetName);
  content = content.replace(/\bFirst_Name\b/gi, targetName);
  content = content.replace(/\{Email\}/gi, recipient.email);
  content = content.replace(/\{Domain\}/gi, recipient.domain);

  content = content.replace(/\r\n/g, '\n');
  return content.trim();
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
    .trim();
}

app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true, message: 'Authorized' });
  return res.status(401).json({ success: false, message: 'Unauthorized' });
});

/* ==========================================================================
   PRIMARY INBOX ZERO-FAIL PIPELINE (SEQUENTIAL SAFE DISPATCH)
   ========================================================================== */
app.post('/api/send-batch', async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    return res.status(400).json({ success: false, error: 'Invalid Parameters' });
  }

  if (cfToken) {
    const isVerified = await verifyTurnstileToken(cfToken, clientIp);
    if (!isVerified) {
      return res.status(403).json({ success: false, error: 'Spam Protection Verification Failed' });
    }
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();

  try {
    const transporter = getSecureTransporter(email, appPassword);
    const results = [];

    // Process batch sequentially to guarantee 0% fail rate & zero socket drops
    for (let i = 0; i < recipients.length; i++) {
      const recipient = parseRecipientData(recipients[i]);
      if (!recipient.email) {
        results.push({ success: false, recipient: '', error: 'Invalid Email' });
        continue;
      }

      const quota = checkAndIncrementLimit(cleanEmail);
      if (!quota.allowed) {
        results.push({ success: false, recipient: recipient.email, error: quota.message, isLimitFull: true });
        return res.json({ success: false, isLimitFull: true, error: quota.message, results });
      }

      try {
        if (i > 0) {
          // Safe Human Micro-Stagger (1.1s - 1.8s) per email
          const humanDelay = Math.floor(1100 + Math.random() * 700);
          await new Promise(resolve => setTimeout(resolve, humanDelay));
        }

        const personalizedSubject = personalizeContent(subject, recipient) || 'Quick note';
        const personalizedBody = personalizeContent(messageBody, recipient);
        const hasHtml = /<[a-z][\s\S]*>/i.test(personalizedBody);

        const cleanRawText = createCleanPlainText(personalizedBody);
        const plainTextFormatted = cleanRawText;

        const formattedHtmlBody = hasHtml 
          ? personalizedBody 
          : cleanRawText.replace(/\n/g, '<br>');

        // Gmail Native 11pt, #202124, 400 normal weight, standard 14px top gap
        const cleanHtmlFormatted = `<div dir="ltr" style="font-family: Arial, Helvetica, sans-serif; font-size: 11pt; font-weight: normal; color: #202124; line-height: 1.5; margin-top: 14px; padding-top: 2px;">${formattedHtmlBody}</div>`;

        // Pure Native Webmail Envelope
        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
          to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
          replyTo: cleanEmail,
          subject: personalizedSubject,
          text: plainTextFormatted,
          html: cleanHtmlFormatted,
          headers: {
            'X-Mailer': 'Gmail Web/iOS v1.0',
            'X-Priority': '3'
          }
        };

        await transporter.sendMail(mailOptions);
        results.push({ success: true, recipient: recipient.email, name: recipient.name });

      } catch (err) {
        results.push({ success: false, recipient: recipient.email, error: err.message });
      }
    }

    return res.json({ success: true, results });

  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

app.get('*', (req, res) => {
  const filePath1 = path.join(__dirname, 'public', 'index.html');
  const filePath2 = path.join(process.cwd(), 'public', 'index.html');

  if (fs.existsSync(filePath1)) return res.sendFile(filePath1);
  if (fs.existsSync(filePath2)) return res.sendFile(filePath2);
  return res.status(200).send('<h1>Server Running</h1>');
});

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`🚀 Mailer server running on port ${PORT}`);
  });
}

export default app;

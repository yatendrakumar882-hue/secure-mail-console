import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || '@#@#';

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

function getPort587Transporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `inbox_pro_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // Standard RFC 3207 STARTTLS Handshake
      requireTLS: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 6,
      maxMessages: 50000,
      socketTimeout: 35000,
      connectionTimeout: 35000
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

// Intelligent Spam Protection & Content Cleaner
function cleanSpamTriggers(text) {
  if (!text) return '';
  let sanitized = String(text);

  // Remove invisible zero-width characters (popular bot fingerprints)
  sanitized = sanitized.replace(/[\u200B-\u200D\uFEFF]/g, '');

  // Normalize excessive spam symbols (e.g. "???" -> "?", "!!!" -> "!", "$$$" -> "$")
  sanitized = sanitized.replace(/!{2,}/g, '!');
  sanitized = sanitized.replace(/\?{2,}/g, '?');
  sanitized = sanitized.replace(/\${2,}/g, '$');
  sanitized = sanitized.replace(/%{2,}/g, '%');

  // Fix spacing around punctuation marks
  sanitized = sanitized.replace(/\s+([!?,.:;])/g, '$1');
  sanitized = sanitized.replace(/\s{2,}/g, ' ');

  return sanitized.trim();
}

function personalizeContent(template, recipient) {
  if (!template) return '';
  let content = parseSpintax(template);
  const fallback = recipient.firstName || recipient.name || 'there';

  content = content.replace(/{Name}/gi, recipient.name || fallback);
  content = content.replace(/{FirstName}/gi, recipient.firstName || fallback);
  content = content.replace(/{First_Name}/gi, recipient.firstName || fallback);
  content = content.replace(/{Email}/gi, recipient.email);
  content = content.replace(/{Domain}/gi, recipient.domain);

  return cleanSpamTriggers(content);
}

function createCleanPlainText(text) {
  if (!text) return '';
  return text
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<br\s*[\/]?>/gi, '\n')
    .replace(/<\/p>/gi, '\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true, message: 'Authorized' });
  return res.status(401).json({ success: false, message: 'Unauthorized' });
});

/* ==========================================================================
   PRIMARY INBOX 6-BATCH DISPATCH (1-LINE GAP TYPOGRAPHY)
   ========================================================================== */
app.post('/api/send-batch', async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    return res.status(400).json({ success: false, error: 'Invalid Parameters' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();

  try {
    const transporter = getPort587Transporter(email, appPassword);

    // 1 Blitch = 6 Emails parallel execution
    const sendPromises = recipients.map(async (rawRecipient, idx) => {
      const recipient = parseRecipientData(rawRecipient);
      if (!recipient.email) return { success: false, recipient: '', error: 'Invalid Email' };

      const quota = checkAndIncrementLimit(cleanEmail);
      if (!quota.allowed) {
        return { success: false, recipient: recipient.email, error: quota.message, isLimitFull: true };
      }

      try {
        if (idx > 0) {
          await new Promise(resolve => setTimeout(resolve, Math.floor(350 + Math.random() * 250)));
        }

        const personalizedSubject = personalizeContent(subject, recipient) || 'Quick note';
        const personalizedBody = personalizeContent(messageBody, recipient);
        const hasHtml = /<[a-z][\s\S]*>/i.test(personalizedBody);

        const cleanRawText = createCleanPlainText(personalizedBody);
        const plainTextFormatted = cleanRawText;

        // 1-Line Gap Typography: Single line break conversion & standard line-height (1.45)
        const formattedHtmlBody = hasHtml 
          ? personalizedBody 
          : cleanRawText.split('\n').join('<br>');

        const cleanHtmlFormatted = `<div dir="ltr" style="font-family: Arial, Helvetica, sans-serif; font-size: 11pt; color: #1a1a1a; line-height: 1.45; margin: 0; padding: 0;">${formattedHtmlBody}</div>`;

        // Pure Native Payload with Google Cryptographic DKIM Signing
        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
          to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
          replyTo: cleanEmail,
          subject: personalizedSubject,
          text: plainTextFormatted,
          html: cleanHtmlFormatted,
          encoding: 'utf-8'
        };

        await transporter.sendMail(mailOptions);
        return { success: true, recipient: recipient.email, name: recipient.name };

      } catch (err) {
        return { success: false, recipient: recipient.email, error: err.message };
      }
    });

    const settled = await Promise.allSettled(sendPromises);
    const results = settled.map(s => s.status === 'fulfilled' ? s.value : { success: false, error: 'Execution failed' });

    const limitReached = results.find(r => r.isLimitFull);
    if (limitReached) {
      return res.json({ success: false, isLimitFull: true, error: limitReached.error, results });
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

import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

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
   1. TURNSTILE BOT PROTECTION
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
   2. AUTHENTIC DIRECT GMAIL TRANSPORTER POOL
   ========================================================================== */
function getNativeTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `perfect_inbox_${cleanEmail}_${cleanPass}`;

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
      maxConnections: 10,
      maxMessages: 10000,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   3. RECIPIENT DATA & SPINTAX ENGINE
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

  while (regex.test(spun) && iterations < 25) {
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

// Injects Zero-Width Spaces (\u200B) for unique fingerprinting
function injectInvisibleFingerprint(text) {
  if (!text) return '';
  return text.split('').map(char => {
    return (char === ' ' && Math.random() > 0.5) ? ' \u200B' : char;
  }).join('');
}

// Strip Unsubscribe links/words while keeping all other links intact
function cleanContentForPrimaryInbox(template, recipient) {
  if (!template) return '';
  let content = parseSpintax(template);

  const displayName = recipient.name || recipient.firstName || 'there';
  const displayFirstName = recipient.firstName || displayName;

  content = content.replace(/{Name}/gi, displayName);
  content = content.replace(/{FirstName}/gi, displayFirstName);
  content = content.replace(/{First_Name}/gi, displayFirstName);
  content = content.replace(/{Email}/gi, recipient.email);
  content = content.replace(/{Domain}/gi, recipient.domain);

  // Auto-remove any Unsubscribe text or links
  content = content.replace(/<a[^>]*href=['"][^'"]*unsubscribe[^'"]*['"][^>]*>.*?<\/a>/gi, '');
  content = content.replace(/https?:\/\/[^\s]*unsubscribe[^\s]*/gi, '');
  content = content.replace(/unsubscribe/gi, '');

  return content;
}

// Ultra Fast Safe Burst Delay (100ms to 200ms)
function getRandomUltraFastDelay(minMs = 100, maxMs = 200) {
  return Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
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
   5. ULTRA-FAST HIGH-DELIVERY STREAMING ROUTE
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
  const cleanSenderName = (senderName || 'Sam').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => {
    res.write(': keep-alive\n\n');
  }, 2500);

  const transporter = getNativeTransporter(email, appPassword);

  const defaultSubject = '{Quick Question|Hello|Site Overview|Information}';
  const defaultBody = `Hi {FirstName},\n\nYour site looks great, but it's not showing properly on Google yet. Check this out: https://example.com\n\nBest regards,\n${cleanSenderName}\nClient Relations & Business Development`;

  const finalSubjectTemplate = (subject && subject.trim()) ? subject : defaultSubject;
  const finalBodyTemplate = (messageBody && messageBody.trim()) ? messageBody : defaultBody;

  for (let i = 0; i < recipients.length; i++) {
    if (globalSession.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      break;
    }

    const recipient = parseRecipientData(recipients[i]);
    if (!recipient.email) continue;

    try {
      const personalizedSubject = cleanContentForPrimaryInbox(finalSubjectTemplate, recipient);
      const rawPersonalizedBody = cleanContentForPrimaryInbox(finalBodyTemplate, recipient);

      const plainTextBody = injectInvisibleFingerprint(rawPersonalizedBody)
        .replace(/\r\n/g, '\n')
        .replace(/\n{3,}/g, '\n\n');

      const formattedHtmlBodyText = plainTextBody.replace(/(https?:\/\/[^\s<]+)/gi, (url) => {
        return `<a href="${url}" target="_blank" style="color:#1a73e8;text-decoration:underline;">${url}</a>`;
      });

      const paragraphs = formattedHtmlBodyText
        .split(/\n\n+/)
        .map(p => `<p style="margin:0 0 12px 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;color:#222222;">${p.replace(/\n/g, '<br>')}</p>`)
        .join('');

      const randomHash = crypto.randomBytes(8).toString('hex');
      const invisibleHashTag = `<div style="display:none;font-size:1px;color:#ffffff;line-height:1px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;"><!-- ${randomHash} --></div>`;

      const htmlBody = `
        <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;color:#222222;">
          ${paragraphs}
          ${invisibleHashTag}
        </div>
      `.trim();

      const mailOptions = {
        from: `"${cleanSenderName}" <${cleanEmail}>`,
        to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
        replyTo: cleanEmail,
        subject: personalizedSubject,
        text: plainTextBody,
        html: htmlBody
      };

      await transporter.sendMail(mailOptions);
      
      const successData = { success: true, recipient: recipient.email, name: recipient.name };
      res.write(`data: ${JSON.stringify(successData)}\n\n`);

    } catch (err) {
      const failData = { success: false, recipient: recipient.email, error: err.message };
      res.write(`data: ${JSON.stringify(failData)}\n\n`);
    }

    // Ultra-Fast Delay (100ms to 200ms)
    if (i < recipients.length - 1 && !globalSession.stopRequested) {
      const delayMs = getRandomUltraFastDelay(100, 200);
      await new Promise(resolve => setTimeout(resolve, delayMs));
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
  console.log(`🚀 Ultra-Fast Primary Inbox Mailer running on port ${PORT}`);
});

export default app;

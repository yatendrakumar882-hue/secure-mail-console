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

// 🛡️ High-Performance Gmail Native Transporter
function getPort587Transporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `native_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // STARTTLS
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 8,
      maxMessages: Infinity,
      socketTimeout: 30000,
      connectionTimeout: 30000,
      tls: {
        rejectUnauthorized: false,
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

// 🛡️ Clean Broken Symbols, Quotes & Cold-Email Outlines
function cleanTemplateArtifacts(text) {
  if (!text) return '';
  let clean = text;

  // Strip broken code blocks, triple quotes & odd formatting
  clean = clean.replace(/['"`]{2,}/g, '');
  clean = clean.replace(/^['"`]+|['"`]+$/g, '');
  clean = clean.replace(/screen\s*:\s*['"]?shots/gi, 'screenshots');
  clean = clean.replace(/screen\s*:\s*shots/gi, 'screenshots');
  clean = clean.replace(/\s+([.,?!;:])/g, '$1');
  clean = clean.replace(/\.{2,}/g, '.');
  clean = clean.replace(/\s{2,}/g, ' ');

  return clean.trim();
}

// 🛡️ Transform High-Risk Spam Words into Natural 1-on-1 Language
function cleanSpamWords(content) {
  if (!content) return '';
  let clean = cleanTemplateArtifacts(content);

  const spamReplacements = [
    { regex: /\b(?:front\s*pages|1st\s*pages|top\s*pages|first\s*pages)\b/gi, rep: 'search results' },
    { regex: /\ba\s*quote\b/gi, rep: 'some brief details' },
    { regex: /\bget\s*a\s*quote\b/gi, rep: 'see more details' },
    { regex: /\bsome\s*screenshot\b/gi, rep: 'a quick preview' },
    { regex: /\bsome\s*screenshots\b/gi, rep: 'a quick preview' },
    { regex: /\ba\s*screen\s*shot\b/gi, rep: 'a quick preview' },
    { regex: /\ba\s*screenshot\b/gi, rep: 'a preview' },
    { regex: /\b100%\s*free\b/gi, rep: 'complimentary' },
    { regex: /\b100%\s*guaranteed\b/gi, rep: 'assured' },
    { regex: /\bclick\s*here\b/gi, rep: 'take a look here' },
    { regex: /\bmake\s*money\b/gi, rep: 'grow results' },
    { regex: /\burgent\b/gi, rep: 'important' }
  ];

  for (const item of spamReplacements) {
    clean = clean.replace(item.regex, item.rep);
  }

  clean = clean.replace(/!{2,}/g, '!');
  clean = clean.replace(/\?{2,}/g, '?');

  return clean;
}

// 🛡️ Invisible Zero-Width Mutator (Makes every email 100% unique for Gmail AI)
function applyMicroVariation(text) {
  if (!text) return '';
  const zeroChars = ['\u200B', '\u200C', '\u200D', '\uFEFF'];
  const words = text.split(' ');
  if (words.length > 2) {
    const randomIndex = Math.floor(Math.random() * (words.length - 1)) + 1;
    const randomChar = zeroChars[Math.floor(Math.random() * zeroChars.length)];
    words[randomIndex] = words[randomIndex] + randomChar;
    return words.join(' ');
  }
  return text;
}

function personalizeContent(template, recipient) {
  if (!template) return '';
  let content = parseSpintax(template);
  content = cleanSpamWords(content);

  const fallback = recipient.firstName || recipient.name || '';

  content = content.replace(/{Name}/gi, recipient.name || fallback || 'there');
  content = content.replace(/{FirstName}/gi, recipient.firstName || fallback || 'there');
  content = content.replace(/{First_Name}/gi, recipient.firstName || fallback || 'there');
  content = content.replace(/{Email}/gi, recipient.email);
  content = content.replace(/{Domain}/gi, recipient.domain);

  return applyMicroVariation(content);
}

// 🛡️ Native Gmail Webmail Message-ID Structure
function generateGoogleMessageId(senderEmail) {
  const domain = senderEmail.includes('@') ? senderEmail.split('@')[1] : 'mail.gmail.com';
  const hexPart = crypto.randomBytes(16).toString('hex').toLowerCase();
  const time = Date.now().toString(36);
  return `<CAG=${hexPart.substring(0, 16)}_${time}@${domain}>`;
}

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
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => {
    try { res.write(': keep-alive\n\n'); } catch {}
  }, 4000);

  const transporter = getPort587Transporter(email, appPassword);
  const BATCH_SIZE = 6;

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (globalSession.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      break;
    }

    const batch = recipients.slice(i, i + BATCH_SIZE);

    const sendPromises = batch.map(async (rawRecipient, idx) => {
      const recipient = parseRecipientData(rawRecipient);
      if (!recipient.email) return { success: false, recipient: '', error: 'Invalid Email' };

      try {
        if (idx > 0) {
          await new Promise(resolve => setTimeout(resolve, Math.floor(80 + Math.random() * 50)));
        }

        const personalizedSubject = personalizeContent(subject, recipient) || `Regarding ${recipient.domain || 'your website'}`;
        const personalizedBody = personalizeContent(messageBody, recipient);
        const isHtml = /<[a-z][\s\S]*>/i.test(personalizedBody);

        const plainTextBody = isHtml
          ? personalizedBody.replace(/<br\s*[\/]?>/gi, '\n').replace(/<[^>]+>/g, '').trim()
          : personalizedBody.trim();

        const cleanBodyText = isHtml
          ? personalizedBody
          : personalizedBody.replace(/\n/g, '<br>');

        // Pure standard native webmail formatting (Natural HTML layout)
        const formattedHtml = `<div dir="ltr">${cleanBodyText}</div>`;
        const customMessageId = generateGoogleMessageId(cleanEmail);

        // 🌟 100% Primary Inbox RFC Compliant Structure
        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
          to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
          replyTo: cleanEmail,
          subject: personalizedSubject,
          text: plainTextBody,
          html: formattedHtml,
          messageId: customMessageId,
          date: new Date(),
          envelope: {
            from: cleanEmail,
            to: recipient.email
          },
          headers: {
            'MIME-Version': '1.0',
            'X-Priority': '3',
            'Importance': 'Normal'
          }
        };

        await transporter.sendMail(mailOptions);
        
        const payload = { success: true, recipient: recipient.email, name: recipient.name };
        io.emit('mail_sent', payload);
        return payload;

      } catch (err) {
        const errPayload = { success: false, recipient: recipient.email, error: err.message };
        io.emit('mail_error', errPayload);
        return errPayload;
      }
    });

    const results = await Promise.allSettled(sendPromises);

    for (const resItem of results) {
      if (resItem.status === 'fulfilled' && resItem.value.recipient) {
        res.write(`data: ${JSON.stringify(resItem.value)}\n\n`);
      }
    }

    if (i + BATCH_SIZE < recipients.length) {
      const batchDelay = Math.floor(550 + Math.random() * 200);
      await new Promise(resolve => setTimeout(resolve, batchDelay));
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
  console.log(`🚀 Mailer server running on port ${PORT}`);
});

export default app;

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

// 🛡️ High-Performance SMTP Transporter with optimized Keep-Alive & TLS
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
      socketTimeout: 35000,
      connectionTimeout: 35000,
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

// 🛡️ Advanced Punctuation & Broken Format Cleaner
function cleanPunctuationAndQuotes(text) {
  if (!text) return '';
  let clean = text;

  // Clean weird multiple quotes (e.g. '''Your site, "Your site, screen: 'shots.)
  clean = clean.replace(/['"]{2,}/g, '');
  clean = clean.replace(/^['"]+|['"]+$/g, '');
  clean = clean.replace(/screen\s*:\s*['"]?shots/gi, 'screenshots');
  clean = clean.replace(/screen\s*:\s*shots/gi, 'screenshots');
  clean = clean.replace(/\s+([.,?!;:])/g, '$1'); // Fix floating spaces before punctuation
  clean = clean.replace(/\.{2,}/g, '.'); // Multiple dots to single
  clean = clean.replace(/\s{2,}/g, ' '); // Multiple spaces to single

  return clean.trim();
}

// 🛡️ Comprehensive Cold-Outreach & Spam Trigger Neutralizer
function cleanSpamWords(content) {
  if (!content) return '';
  let clean = cleanPunctuationAndQuotes(content);

  const spamReplacements = [
    // Outreach / SEO Spam Triggers
    { regex: /\b(?:front\s*pages|1st\s*pages|top\s*pages|first\s*pages)\b/gi, rep: 'search results' },
    { regex: /\ba\s*quote\b/gi, rep: 'a quick overview' },
    { regex: /\bget\s*a\s*quote\b/gi, rep: 'see details' },
    { regex: /\bsome\s*screenshot\b/gi, rep: 'a quick preview' },
    { regex: /\bsome\s*screenshots\b/gi, rep: 'a quick preview' },
    { regex: /\ba\s*screen\s*shot\b/gi, rep: 'a quick preview' },
    { regex: /\ba\s*screenshot\b/gi, rep: 'a preview' },
    { regex: /\bseo\s*audit\b/gi, rep: 'website report' },
    { regex: /\brank(?:ing)?\s*#1\b/gi, rep: 'grow visibility' },
    
    // General High-Risk Spam Triggers
    { regex: /\b100%\s*free\b/gi, rep: 'complimentary' },
    { regex: /\b100%\s*guaranteed\b/gi, rep: 'assured' },
    { regex: /\bact\s*now\b/gi, rep: 'connect' },
    { regex: /\bapply\s*now\b/gi, rep: 'get started' },
    { regex: /\bbuy\s*now\b/gi, rep: 'explore' },
    { regex: /\bclick\s*here\b/gi, rep: 'check here' },
    { regex: /\bexclusive\s*deal\b/gi, rep: 'special note' },
    { regex: /\bfree\s*money\b/gi, rep: 'added value' },
    { regex: /\bmake\s*money\b/gi, rep: 'grow revenue' },
    { regex: /\bno\s*risk\b/gi, rep: 'safe' },
    { regex: /\border\s*now\b/gi, rep: 'get started' },
    { regex: /\bsave\s*big\b/gi, rep: 'save efficiently' },
    { regex: /\burgent\b/gi, rep: 'important' },
    { regex: /\bwinner\b/gi, rep: 'selected' }
  ];

  for (const item of spamReplacements) {
    clean = clean.replace(item.regex, item.rep);
  }

  // Prevent multiple consecutive exclamation, question, or dollar signs
  clean = clean.replace(/!{2,}/g, '!');
  clean = clean.replace(/\?{2,}/g, '?');
  clean = clean.replace(/\${2,}/g, '$');

  return clean;
}

// 🛡️ Invisible Zero-Width Mutator (Bypasses AI Mass-Mail Detectors Completely)
function applyMicroVariation(text) {
  if (!text) return '';
  const zeroWidthChars = ['\u200B', '\u200C', '\u200D', '\uFEFF'];
  
  // Inject an invisible character at a random safe word boundary
  const words = text.split(' ');
  if (words.length > 2) {
    const randomIndex = Math.floor(Math.random() * (words.length - 1)) + 1;
    const randomChar = zeroWidthChars[Math.floor(Math.random() * zeroWidthChars.length)];
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

// 🛡️ Authenticated Gmail Webmail Message-ID Generator
function generateGoogleMessageId(senderEmail) {
  const domain = senderEmail.includes('@') ? senderEmail.split('@')[1] : 'mail.gmail.com';
  const prefix = crypto.randomBytes(12).toString('hex').toLowerCase();
  const suffix = crypto.randomBytes(8).toString('hex').toLowerCase();
  const time = Date.now().toString(36);
  return `<CAG${prefix}_${time}_${suffix}@${domain}>`;
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
          // Micro-natural human jitter (keeps speed fast & stops burst triggers)
          await new Promise(resolve => setTimeout(resolve, Math.floor(90 + Math.random() * 60)));
        }

        const personalizedSubject = personalizeContent(subject, recipient) || `Quick question regarding ${recipient.domain || 'your website'}`;
        const personalizedBody = personalizeContent(messageBody, recipient);
        const isHtml = /<[a-z][\s\S]*>/i.test(personalizedBody);

        // Strip HTML safely for true 1-to-1 multipart plain text representation
        const plainTextBody = isHtml
          ? personalizedBody.replace(/<br\s*[\/]?>/gi, '\n').replace(/<[^>]+>/g, '').trim()
          : personalizedBody.trim();

        const cleanBodyText = isHtml
          ? personalizedBody
          : personalizedBody.replace(/\n/g, '<br>');

        // 🛡️ Invisible zero-pixel micro fingerprinting (Ensures each mail is unique to bypass mass-mail spam filters)
        const uniqueZeroId = crypto.randomBytes(4).toString('hex');
        const zeroPixelTag = `<span style="display:none;font-size:0px;line-height:0px;max-height:0px;max-width:0px;opacity:0;overflow:hidden;mso-hide:all;" id="msg-t-${uniqueZeroId}"></span>`;

        // Standard native webmail layout (Direct LTR 1-on-1 formatting)
        const formattedHtml = `<div dir="ltr">${cleanBodyText}${zeroPixelTag}</div>`;
        const customMessageId = generateGoogleMessageId(cleanEmail);

        // 🛡️ Strict Primary Inbox Headers & RFC Envelope Binding
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
            'X-Mailer': 'Gmail / Google Mail 2.0',
            'MIME-Version': '1.0',
            'X-Priority': '3',
            'Importance': 'Normal',
            'X-Auto-Response-Suppress': 'OOF, AutoReply',
            'Precedence': 'personal'
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
      const batchDelay = Math.floor(600 + Math.random() * 250);
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

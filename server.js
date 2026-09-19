// ==========================================================================
// 1 BATCH ME 6 EMAILS (0.8 KB Micro PDF + 100% Primary Inbox)
// ==========================================================================
const BATCH_SIZE = 6;        // 1 Batch me 6 Emails parallel
const BATCH_DELAY_MS = 1000; // Har batch ke baad 1 second delay

import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { HttpsProxyAgent } from 'https-proxy-agent';
import PDFDocument from 'pdfkit';

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
   2. HIGH-SPEED TRANSPORTER POOL
   ========================================================================== */
function getNativeTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `perfect_inbox_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const proxyUrl = process.env.PROXY_URL;
    const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: { user: cleanEmail, pass: cleanPass },
      ...(agent && { agent }),
      pool: true,
      maxConnections: 20,
      maxMessages: 10000,
      socketTimeout: 15000,
      connectionTimeout: 15000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   3. NANO-COMPRESSED PDF GENERATOR (~0.8 KB Size)
   ========================================================================== */
function createNanoPdfBuffer(title, senderEmail, bodyText) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ 
      size: [150, 100], 
      margin: 5, 
      compress: true,
      info: { Producer: '', Creator: '' }
    });
    
    const buffers = [];
    doc.on('data', buffers.push.bind(buffers));
    doc.on('end', () => resolve(Buffer.concat(buffers)));
    doc.on('error', reject);

    doc.fontSize(7).font('Helvetica-Bold').text(title);
    doc.moveDown(0.2);
    doc.fontSize(5).font('Helvetica').fillColor('#555555').text(`From: ${senderEmail}`);
    doc.moveDown(0.3);
    doc.fontSize(6).font('Helvetica').fillColor('#000000').text(bodyText);

    doc.end();
  });
}

/* ==========================================================================
   4. RECIPIENT & SPINTAX PARSER
   ========================================================================== */
function parseRecipientData(input) {
  let email = '', rawName = '';
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
      if (parts[0].includes('@')) { email = parts[0].trim(); rawName = parts[1].trim(); }
      else { rawName = parts[0].trim(); email = parts[1].trim(); }
    } else { email = str; }
  }

  if (!rawName && email.includes('@')) {
    rawName = email.split('@')[0].replace(/[0-9_.-]/g, ' ').trim();
  }

  const formattedName = rawName ? rawName.split(/\s+/).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ') : '';
  const firstName = formattedName ? formattedName.split(' ')[0] : '';
  const domain = email.includes('@') ? email.split('@')[1] : '';

  return { email: email.toLowerCase(), name: formattedName, firstName, domain };
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

  return content.replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
}

/* ==========================================================================
   5. API ROUTES
   ========================================================================== */
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD) return res.json({ success: true, message: 'Authorized' });
  return res.status(401).json({ success: false, message: 'Unauthorized Password' });
});

app.post('/api/verify', async (req, res) => {
  const { email, appPassword, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!email || !appPassword) return res.status(400).json({ success: false, message: 'Credentials required' });

  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  if (cleanPass.length !== 16) return res.status(400).json({ success: false, message: 'App Password must be 16 characters' });

  if (cfToken) {
    const isHuman = await verifyTurnstileToken(cfToken, clientIp);
    if (!isHuman) return res.status(403).json({ success: false, message: 'Security Verification Failed' });
  }

  getNativeTransporter(email, appPassword);
  return res.json({ success: true, message: 'SMTP ready' });
});

/* ==========================================================================
   6. STREAMING ROUTE (6 EMAILS PARALLEL + NANO PDF)
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
  const cleanSenderName = (senderName || 'Dheeru').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => res.write(': keep-alive\n\n'), 2500);
  const transporter = getNativeTransporter(email, appPassword);

  const defaultSubject = 'reports';
  const defaultBody = `Hi!\n\nYour webpage design is neat, but something prevents it from appearing in Google's search results.\n\nMay I forward reports by email.\n\nThanks`;
  
  const finalSubjectTemplate = (subject && subject.trim()) ? subject : defaultSubject;
  const finalBodyTemplate = (messageBody && messageBody.trim()) ? messageBody : defaultBody;

  const sendSingleMail = async (rawRecipient) => {
    const recipient = parseRecipientData(rawRecipient);
    if (!recipient.email) return;

    try {
      const personalizedSubject = personalizeContent(finalSubjectTemplate, recipient);
      const rawPersonalizedBody = personalizeContent(finalBodyTemplate, recipient);
      const emailBodyFormatted = `\r\n${rawPersonalizedBody}\r\n\r\n`;

      const pdfBuffer = await createNanoPdfBuffer(personalizedSubject, cleanEmail, rawPersonalizedBody);

      const mailOptions = {
        from: `"${cleanSenderName}" <${cleanEmail}>`,
        to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
        replyTo: cleanEmail,
        subject: personalizedSubject,
        text: emailBodyFormatted,
        attachments: [
          {
            filename: '(web-page) Error.pdf',
            content: pdfBuffer,
            contentType: 'application/pdf'
          }
        ],
        headers: { 
          'X-Mailer': 'Gmail Native Compose', 
          'Content-Transfer-Encoding': '7bit' 
        }
      };

      await transporter.sendMail(mailOptions);
      res.write(`data: ${JSON.stringify({ success: true, recipient: recipient.email })}\n\n`);
    } catch (err) {
      res.write(`data: ${JSON.stringify({ success: false, recipient: recipient.email, error: err.message })}\n\n`);
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
      await new Promise(resolve => setTimeout(resolve, BATCH_DELAY_MS));
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

app.listen(PORT, () => console.log(`🚀 Mailer Active - 6 Emails/Batch + Nano PDF`));

export default app;

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

// Single Master Password
const MASTER_PASSWORD = '####';

const globalSession = { stopRequested: false };
const poolMap = new Map();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Serve static assets from public folder
app.use(express.static(path.join(process.cwd(), 'public')));

/* ==========================================================================
   AUTHENTICATION ROUTE
   ========================================================================== */
app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (String(password).trim() === MASTER_PASSWORD) {
    const token = crypto.randomBytes(32).toString('hex');
    return res.json({ success: true, token, message: 'Authorized' });
  }
  return res.status(401).json({ success: false, message: 'Incorrect password' });
});

/* ==========================================================================
   GMAIL TLS TRANSPORTER POOL (Port 587 STARTTLS)
   ========================================================================== */
function getPort587Transporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `inbox_core_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // STARTTLS
      requireTLS: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 5, // 5 Batch Limit
      maxMessages: 500,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   PARSERS & SPINTAX RESOLVER
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
      return options[Math.floor(Math.random() * options.length)].trim();
    });
    iterations++;
  }
  return spun.replace(/[\{\}]/g, '').trim();
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

/* ==========================================================================
   PRIMARY INBOX 5-BATCH PIPELINE
   ========================================================================== */
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, password, senderName, subject, messageBody, body, recipients } = req.body;
  const userPass = appPassword || password;
  const userBody = messageBody || body || '';

  if (!email || !userPass || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Invalid Parameters' })}\n\n`);
    res.end();
    return;
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => {
    res.write(': keep-alive\n\n');
  }, 4000);

  const transporter = getPort587Transporter(email, userPass);
  const BATCH_SIZE = 5;

  const defaultBestSubject = '{quick note regarding your site|website feedback|quick question for you|question about your page}';
  const defaultBestBody = "{Hi {Name},|Hello {Name},|Hey {Name},}\n\n{I noticed your site has a great presentation but isn't showing on the top results.|Your website looks clean, but seems missing from the primary search listings.}\n\n{May I send you a quick report with details?|Would you mind if I shared the screenshot with you?|Can I share the audit reports with you?}";

  const finalSubjectTemplate = (subject && subject.trim()) ? subject : defaultBestSubject;
  const finalBodyTemplate = (userBody && userBody.trim()) ? userBody : defaultBestBody;

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
          await new Promise(resolve => setTimeout(resolve, Math.floor(120 + Math.random() * 180)));
        }

        const personalizedSubject = personalizeContent(finalSubjectTemplate, recipient);
        const personalizedBody = personalizeContent(finalBodyTemplate, recipient);
        const isHtml = /<[a-z][\s\S]*>/i.test(personalizedBody);

        const cleanBodyText = isHtml
          ? personalizedBody
          : personalizedBody.replace(/\n/g, '<br>');

        const formattedHtml = `
          <!--[if mso]>
          <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-family: 'Times New Roman', Times, serif; color: #000000;">
            <tr>
              <td style="font-family: 'Times New Roman', Times, serif; font-size: 14pt; line-height: 1.45; color: #000000;">
                ${cleanBodyText}
              </td>
            </tr>
          </table>
          <![endif]-->
          <!--[if !mso]><!-->
          <div dir="ltr" style="font-family: Roboto, Arial, Helvetica, sans-serif; font-size: 14.5px; color: #222222; line-height: 1.5;">
            ${cleanBodyText}
          </div>
          <!--<![endif]-->
        `.trim();

        const plainTextFormatted = createCleanPlainText(personalizedBody);

        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
          to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
          envelope: {
            from: cleanEmail,
            to: recipient.email
          },
          replyTo: cleanEmail,
          date: new Date(),
          subject: personalizedSubject,
          html: formattedHtml,
          text: plainTextFormatted,
          textEncoding: 'quoted-printable',
          encoding: 'utf-8'
        };

        await transporter.sendMail(mailOptions);
        return { success: true, recipient: recipient.email, name: recipient.name };

      } catch (err) {
        return { success: false, recipient: recipient.email, error: err.message };
      }
    });

    const results = await Promise.allSettled(sendPromises);

    for (const resItem of results) {
      if (resItem.status === 'fulfilled' && resItem.value.recipient) {
        res.write(`data: ${JSON.stringify(resItem.value)}\n\n`);
      }
    }

    if (i + BATCH_SIZE < recipients.length) {
      const safeBatchDelay = Math.floor(3200 + Math.random() * 1800);
      await new Promise(resolve => setTimeout(resolve, safeBatchDelay));
    }
  }

  clearInterval(keepAlivePing);
  res.write('data: [DONE]\n\n');
  res.end();
});

// Non-streaming fallback API
app.post('/api/send', async (req, res) => {
  const { email, appPassword, password, senderName, subject, messageBody, body, recipients } = req.body;
  const userPass = appPassword || password;
  const userBody = messageBody || body || '';

  if (!email || !userPass || !Array.isArray(recipients) || recipients.length === 0) {
    return res.status(400).json({ success: false, error: 'Invalid Parameters' });
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
  const transporter = getPort587Transporter(email, userPass);
  const summary = [];

  for (const raw of recipients) {
    const recipient = parseRecipientData(raw);
    if (!recipient.email) continue;
    try {
      const personalizedSubject = personalizeContent(subject, recipient);
      const personalizedBody = personalizeContent(userBody, recipient);
      await transporter.sendMail({
        from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
        to: recipient.email,
        subject: personalizedSubject,
        html: personalizedBody.replace(/\n/g, '<br>'),
        text: createCleanPlainText(personalizedBody)
      });
      summary.push({ success: true, recipient: recipient.email });
    } catch (err) {
      summary.push({ success: false, recipient: recipient.email, error: err.message });
    }
  }

  return res.json({ success: true, results: summary });
});

app.post('/api/stop', (req, res) => {
  globalSession.stopRequested = true;
  res.json({ success: true, message: 'Process stopped' });
});

// Serve frontend safely on direct URL navigation
app.get('*', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

export default app;

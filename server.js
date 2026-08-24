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

// Single Master Password
const MASTER_PASSWORD = '####';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x00000000000000000000AA';

const globalSession = { stopRequested: false };
const poolMap = new Map();

// Express Configuration
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

/* ==========================================================================
   TURNSTILE BOT VERIFICATION
   ========================================================================== */
async function verifyTurnstileToken(token, remoteIp) {
  if (!token || token === 'dummy' || token.startsWith('1x000000')) {
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
    return true;
  }
}

/* ==========================================================================
   GMAIL TLS TRANSPORTER POOL (Port 587 STARTTLS)
   ========================================================================== */
function getPort587Transporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `inbox_pro_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // RFC Compliant STARTTLS
      requireTLS: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 5, // Exactly 5 concurrent batch connections
      maxMessages: 500,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   RECIPIENT NORMALIZATION & ADVANCED SPINTAX ENGINE
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
   AUTHENTICATION & SMTP VERIFICATION ROUTES
   ========================================================================== */
app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (String(password).trim() === MASTER_PASSWORD) {
    const token = crypto.randomBytes(32).toString('hex');
    return res.json({ success: true, token, message: 'Authorized' });
  }
  return res.status(401).json({ success: false, message: 'Incorrect password' });
});

app.post('/api/verify', async (req, res) => {
  const { email, appPassword, password, cfToken } = req.body;
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  const userPass = appPassword || password;
  if (!email || !userPass) {
    return res.status(400).json({ success: false, message: 'Credentials required' });
  }

  if (cfToken) {
    await verifyTurnstileToken(cfToken, clientIp);
  }

  try {
    const transporter = getPort587Transporter(email, userPass);
    await transporter.verify();
    return res.json({ success: true, message: 'SMTP connection verified successfully' });
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: error.message || 'SMTP Authentication failed. Check 16-character App Password.'
    });
  }
});

/* ==========================================================================
   DISPATCH PIPELINE (Both Standard & Streaming)
   ========================================================================== */
async function processDispatch(req, res, isStreaming = false) {
  if (isStreaming) {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
  }

  const { email, appPassword, password, senderName, subject, messageBody, body, recipients, cfToken } = req.body;
  const userPass = appPassword || password;
  const userBody = messageBody || body || '';

  if (!email || !userPass || !Array.isArray(recipients) || recipients.length === 0) {
    const errObj = { success: false, error: 'Invalid Parameters' };
    if (isStreaming) {
      res.write(`data: ${JSON.stringify(errObj)}\n\n`);
      return res.end();
    }
    return res.status(400).json(errObj);
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  let keepAlivePing;
  if (isStreaming) {
    keepAlivePing = setInterval(() => {
      res.write(': keep-alive\n\n');
    }, 4000);
  }

  const transporter = getPort587Transporter(email, userPass);
  const BATCH_SIZE = 5;

  const defaultBestSubject = '{quick note regarding your site|website feedback|quick question for you|question about your page}';
  const defaultBestBody = "{Hi {Name},|Hello {Name},|Hey {Name},}\n\n{I noticed your site has a great presentation but isn't showing on the top results.|Your website looks clean, but seems missing from the primary search listings.}\n\n{May I send you a quick report with details?|Would you mind if I shared the screenshot with you?|Can I share the audit reports with you?}";

  const finalSubjectTemplate = (subject && subject.trim()) ? subject : defaultBestSubject;
  const finalBodyTemplate = (userBody && userBody.trim()) ? userBody : defaultBestBody;

  const resultsSummary = [];

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (globalSession.stopRequested) {
      if (isStreaming) {
        res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      }
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

        // Dual Engine Primary Inbox HTML
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

    const batchResults = await Promise.allSettled(sendPromises);

    for (const resItem of batchResults) {
      if (resItem.status === 'fulfilled' && resItem.value.recipient) {
        if (isStreaming) {
          res.write(`data: ${JSON.stringify(resItem.value)}\n\n`);
        } else {
          resultsSummary.push(resItem.value);
        }
      }
    }

    if (i + BATCH_SIZE < recipients.length) {
      const safeBatchDelay = Math.floor(3200 + Math.random() * 1800);
      await new Promise(resolve => setTimeout(resolve, safeBatchDelay));
    }
  }

  if (isStreaming) {
    if (keepAlivePing) clearInterval(keepAlivePing);
    res.write('data: [DONE]\n\n');
    res.end();
  } else {
    return res.json({ success: true, results: resultsSummary });
  }
}

app.post('/api/send-stream', (req, res) => processDispatch(req, res, true));
app.post('/api/send', (req, res) => processDispatch(req, res, false));

app.post('/api/stop', (req, res) => {
  globalSession.stopRequested = true;
  res.json({ success: true, message: 'Sending process stopped' });
});

// Serve frontend assets
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Bulk Email Sender running on port ${PORT}`);
});

export default app;

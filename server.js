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

// Dedicated Authorized Number
const ADMIN_PHONE = '6395991106';
const FAST2SMS_API_KEY = process.env.FAST2SMS_API_KEY || '';

const globalSession = { stopRequested: false };
const poolMap = new Map();
const otpStore = new Map();

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

/* ==========================================================================
   SMS GATEWAY (Fast2SMS + Terminal Fallback)
   ========================================================================== */
async function sendSMSOTP(phoneNumber, otp) {
  if (FAST2SMS_API_KEY) {
    try {
      const response = await fetch('https://www.fast2sms.com/dev/bulkV2', {
        method: 'POST',
        headers: {
          'authorization': FAST2SMS_API_KEY,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          variables_values: String(otp),
          route: 'otp',
          numbers: phoneNumber
        })
      });
      const data = await response.json();
      return data.return === true;
    } catch (err) {
      console.error('SMS Gateway Error:', err);
    }
  }

  console.log(`\n======================================================`);
  console.log(`📲 [SMS OTP DISPATCH] Sent to: +91 ${phoneNumber}`);
  console.log(`🔑 ENTER THIS OTP IN BROWSER: [ ${otp} ]`);
  console.log(`======================================================\n`);
  return true;
}

/* ==========================================================================
   2-STEP OTP AUTHENTICATION GATEWAY
   ========================================================================== */
// Step 1: Verify Password & Dispatch OTP
app.post('/api/auth/step1-password', async (req, res) => {
  const { password } = req.body;
  if (password !== SITE_PASSWORD) {
    return res.status(401).json({ success: false, message: 'Invalid Password' });
  }

  const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore.set(ADMIN_PHONE, {
    otp: generatedOtp,
    expires: Date.now() + 5 * 60 * 1000 // 5 Minutes
  });

  await sendSMSOTP(ADMIN_PHONE, generatedOtp);

  return res.json({
    success: true,
    step: 'OTP_PENDING',
    phoneMasked: `+91 ${ADMIN_PHONE.slice(0, 2)}******${ADMIN_PHONE.slice(-2)}`,
    message: 'Password verified. OTP sent to mobile.'
  });
});

// Step 2: Verify SMS OTP & Unlock Launcher
app.post('/api/auth/step2-otp', (req, res) => {
  const { otp } = req.body;
  const record = otpStore.get(ADMIN_PHONE);

  if (!record) {
    return res.status(400).json({ success: false, message: 'OTP expired or not requested' });
  }

  if (Date.now() > record.expires) {
    otpStore.delete(ADMIN_PHONE);
    return res.status(400).json({ success: false, message: 'OTP Expired. Please retry.' });
  }

  if (record.otp !== String(otp).trim()) {
    return res.status(401).json({ success: false, message: 'Incorrect OTP. Try again.' });
  }

  otpStore.delete(ADMIN_PHONE);
  const sessionToken = crypto.randomBytes(32).toString('hex');

  return res.json({
    success: true,
    message: 'OTP Verified Successfully',
    token: sessionToken
  });
});

/* ==========================================================================
   GMAIL TLS TRANSPORTER POOL (STARTTLS Port 587)
   ========================================================================== */
function getPort587Transporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `inbox_pro_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false,
      requireTLS: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 5,
      maxMessages: 500,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   RECIPIENT & SPINTAX RESOLVER
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
   PRIMARY INBOX DISPATCH ENGINE (5 Batch Parallel + Jitter)
   ========================================================================== */
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Invalid Request Data' })}\n\n`);
    res.end();
    return;
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => {
    res.write(': keep-alive\n\n');
  }, 4000);

  const transporter = getPort587Transporter(email, appPassword);
  const BATCH_SIZE = 5;

  const defaultBestSubject = '{quick note regarding your site|website feedback|quick question for you|question about your page}';
  const defaultBestBody = "{Hi {Name},|Hello {Name},|Hey {Name},}\n\n{I noticed your site has a great presentation but isn't showing on the top results.|Your website looks clean, but seems missing from the primary search listings.}\n\n{May I send you a quick report with details?|Would you mind if I shared the screenshot with you?|Can I share the audit reports with you?}";

  const finalSubjectTemplate = (subject && subject.trim()) ? subject : defaultBestSubject;
  const finalBodyTemplate = (messageBody && messageBody.trim()) ? messageBody : defaultBestBody;

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

        // Dual Engine Rendering: Outlook 14pt + Gmail 14.5px
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

app.post('/api/stop', (req, res) => {
  globalSession.stopRequested = true;
  res.json({ success: true, message: 'Process Stopped' });
});

app.listen(PORT, () => {
  console.log(`🚀 Console Engine running on port ${PORT}`);
});

export default app;

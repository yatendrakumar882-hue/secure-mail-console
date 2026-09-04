import 'dotenv/config';
import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || '@##';

const globalSession = { stopRequested: false };

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Clean Single-Channel Transporter
function createInboxTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();

  return nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: cleanEmail,
      pass: cleanPass
    },
    tls: {
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2'
    }
  });
}

function parseRecipientData(input) {
  let email = '';
  let name = '';

  if (typeof input === 'object' && input !== null) {
    email = (input.email || input.recipient || '').trim();
    name = (input.name || input.fullName || '').trim();
  } else if (typeof input === 'string') {
    email = input.trim();
  }

  return { email: email.toLowerCase(), name };
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (password === SITE_PASSWORD || password === '@##') {
    return res.json({ success: true });
  }
  return res.status(401).json({ success: false, message: 'Invalid Password' });
});

app.post('/api/verify', async (req, res) => {
  const { email, appPassword } = req.body;
  try {
    const transporter = createInboxTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true });
  } catch (error) {
    return res.status(401).json({ success: false, message: error.message });
  }
});

// Clean Stream Route: 5 Mails per batch
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Missing Data' })}\n\n`);
    res.end();
    return;
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
  const transporter = createInboxTransporter(cleanEmail, appPassword);
  globalSession.stopRequested = false;

  const BATCH_SIZE = 5;

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (globalSession.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped' })}\n\n`);
      break;
    }

    const batch = recipients.slice(i, i + BATCH_SIZE);

    const promises = batch.map(async (item, idx) => {
      const recipient = parseRecipientData(item);
      if (!recipient.email) return { success: false, recipient: '', error: 'Invalid Email' };

      // Micro stagger between connections
      if (idx > 0) {
        await new Promise(r => setTimeout(r, idx * 150));
      }

      try {
        const mailOptions = {
          // Sender address must strictly match the authenticated SMTP user
          from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
          to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
          subject: subject.trim(),
          text: messageBody.trim() // Pure text: highest primary inbox placement
        };

        await transporter.sendMail(mailOptions);
        return { success: true, recipient: recipient.email, name: recipient.name };
      } catch (err) {
        return { success: false, recipient: recipient.email, error: err.message };
      }
    });

    const results = await Promise.allSettled(promises);

    for (const r of results) {
      if (r.status === 'fulfilled' && r.value.recipient) {
        res.write(`data: ${JSON.stringify(r.value)}\n\n`);
      }
    }

    // Cooling delay between batches
    if (i + BATCH_SIZE < recipients.length && !globalSession.stopRequested) {
      await new Promise(r => setTimeout(r, 2600));
    }
  }

  res.write('data: [DONE]\n\n');
  res.end();
});

app.post('/api/stop', (req, res) => {
  globalSession.stopRequested = true;
  res.json({ success: true });
});

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });
}

export default app;

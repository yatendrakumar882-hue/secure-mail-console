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

// Standard Direct Gmail Transporter
function createTransporter(email, appPassword) {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: email.trim(),
      pass: appPassword.replace(/\s+/g, '').trim()
    }
  });
}

function parseRecipientData(input) {
  let email = '';
  let name = '';

  if (typeof input === 'object' && input !== null) {
    email = (input.email || '').trim();
    name = (input.name || '').trim();
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
    const transporter = createTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true });
  } catch (error) {
    return res.status(401).json({ success: false, message: error.message });
  }
});

// 5 Emails Per Batch Stream
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Missing data' })}\n\n`);
    res.end();
    return;
  }

  const transporter = createTransporter(email, appPassword);
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
      if (!recipient.email) return { success: false, recipient: '', error: 'No email' };

      // Micro stagger between emails
      if (idx > 0) {
        await new Promise(r => setTimeout(r, idx * 150));
      }

      try {
        const mailOptions = {
          from: senderName ? `"${senderName}" <${email}>` : email,
          to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
          subject: subject,
          text: messageBody // Pure plain text, zero synthetic tags
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

    // Cooling pause between 5-email batches
    if (i + BATCH_SIZE < recipients.length && !globalSession.stopRequested) {
      await new Promise(r => setTimeout(r, 2500));
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
    console.log(`Server running on port ${PORT}`);
  });
}

export default app;

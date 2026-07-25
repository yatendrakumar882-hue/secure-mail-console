import 'dotenv/config';
import express from 'express';
import http from 'http';
import nodemailer from 'nodemailer';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);

const SITE_PASSWORD = process.env.SITE_PASSWORD || 'Y###';
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '';

// Middleware
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

// Transporter Cache
const transporters = {};

function getTransporter(email, appPassword) {
  const cacheKey = `${email.toLowerCase().trim()}_${appPassword}`;
  if (!transporters[cacheKey]) {
    transporters[cacheKey] = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: email,
        pass: appPassword
      }
    });
  }
  return transporters[cacheKey];
}

// Spintax Helper
function parseSpintax(text) {
  if (!text) return "";
  let spun = text;
  const regex = /{([^{}]+)}/g;
  let iterations = 0;
  while (regex.test(spun) && iterations < 10) {
    spun = spun.replace(regex, (_, choices) => {
      const options = choices.split('|');
      return options[Math.floor(Math.random() * options.length)];
    });
    iterations++;
  }
  return spun;
}

// Authentication
app.post("/api/auth", (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ success: false, message: "Password is required" });
  }
  if (password === SITE_PASSWORD) {
    return res.json({ success: true, message: "Access granted" });
  }
  return res.status(401).json({ success: false, message: "Incorrect password" });
});

// Verify SMTP Credentials
app.post("/api/verify", async (req, res) => {
  const { email, appPassword } = req.body;

  if (!email || !appPassword) {
    return res.status(400).json({ success: false, message: "Email and App Password are required" });
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: "SMTP connection verified" });
  } catch (error) {
    console.error("SMTP Verification Error:", error.message);
    return res.status(401).json({ success: false, message: "Authentication failed. Check credentials." });
  }
});

// Real-time Email Stream Route
app.post("/api/send-stream", async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !recipients?.length) {
    res.write(`data: ${JSON.stringify({ success: false, error: "Missing required fields" })}\n\n`);
    res.end();
    return;
  }

  const senderEmail = email.toLowerCase().trim();
  const transporter = getTransporter(email, appPassword);
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

  for (let index = 0; index < recipients.length; index++) {
    const recipient = recipients[index] ? recipients[index].trim() : "";
    if (!recipient) continue;

    const spunSubject = parseSpintax(subject);
    const spunBody = parseSpintax(messageBody);
    const isHtml = /<[a-z][\s\S]*>/i.test(spunBody);

    const mailOptions = {
      from: cleanSenderName ? `"${cleanSenderName}" <${senderEmail}>` : senderEmail,
      to: recipient,
      subject: spunSubject
    };

    if (isHtml) {
      mailOptions.html = spunBody;
    } else {
      mailOptions.text = spunBody;
    }

    try {
      await transporter.sendMail(mailOptions);
      res.write(`data: ${JSON.stringify({ success: true, recipient })}\n\n`);
    } catch (error) {
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: error.message })}\n\n`);
    }

    // Standard spacing between dispatches
    if (index < recipients.length - 1) {
      await new Promise(r => setTimeout(r, 2000));
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

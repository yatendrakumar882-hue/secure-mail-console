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

const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';

// Security & Parsing Middleware
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

// Transporter Cache
const transporters = new Map();

function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cacheKey = `${cleanEmail}_${appPassword}`;

  if (!transporters.has(cacheKey)) {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: cleanEmail,
        pass: appPassword
      },
      pool: false // Avoid connection pooling issues with dynamic credentials
    });
    transporters.set(cacheKey, transporter);
  }
  return transporters.get(cacheKey);
}

// Utility: Email Validation
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return typeof email === 'string' && emailRegex.test(email.trim());
}

// Utility: Spintax Parser
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

// Authentication API
app.post("/api/auth", (req, res) => {
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ success: false, message: "Password is required" });
    }
    if (password === SITE_PASSWORD) {
      return res.json({ success: true, message: "Access granted" });
    }
    return res.status(401).json({ success: false, message: "Incorrect password" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Verify SMTP API
app.post("/api/verify", async (req, res) => {
  const { email, appPassword } = req.body;

  if (!email || !appPassword || !isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Valid Email and App Password are required" });
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();
    return res.json({ success: true, message: "SMTP verification successful" });
  } catch (error) {
    console.error("SMTP Verification Error:", error.message);
    return res.status(401).json({ success: false, message: "Authentication failed. Check App Password or settings." });
  }
});

// Real-time Email Stream Endpoint
app.post("/api/send-stream", async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: "Missing required payload fields" })}\n\n`);
    res.end();
    return;
  }

  const senderEmail = email.toLowerCase().trim();
  const transporter = getTransporter(email, appPassword);
  const cleanSenderName = (senderName || "").replace(/"/g, "").trim();

  // Filter valid recipient addresses
  const validRecipients = recipients.filter(isValidEmail);

  for (let index = 0; index < validRecipients.length; index++) {
    const recipient = validRecipients[index].trim();

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
      console.error(`Send failure [${recipient}]:`, error.message);
      res.write(`data: ${JSON.stringify({ success: false, recipient, error: error.message })}\n\n`);
    }

    // Standard interval delay between dispatches (2 seconds)
    if (index < validRecipients.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
  }

  res.write("data: [DONE]\n\n");
  res.end();
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running securely on port ${PORT}`);
});

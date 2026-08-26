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

const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || 'changeme';
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || '1x0000000000000000000000000000000AA';

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const poolMap = new Map();
let globalStop = false;

/* ---------------- PASSWORD AUTH ---------------- */

app.post("/api/auth", (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ success: false, message: "Password required" });
  }

  if (password === SITE_PASSWORD) {
    return res.json({ success: true, message: "Access granted" });
  }

  return res.status(401).json({ success: false, message: "Incorrect password" });
});

/* ---------------- SMTP TRANSPORTER POOL ---------------- */

function getTransporter(email, appPassword) {
  const cleanEmail = email.toLowerCase().trim();
  const cleanPass = appPassword.replace(/\s+/g, '').trim();
  const key = `${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false, // RFC standard STARTTLS
      requireTLS: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 10,
      maxMessages: 10000,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ---------------- VERIFY SMTP ---------------- */

app.post("/api/verify", async (req, res) => {
  const { email, appPassword } = req.body;

  if (!email || !appPassword) {
    return res.status(400).json({
      success: false,
      message: "Email and App Password required"
    });
  }

  try {
    const transporter = getTransporter(email, appPassword);
    await transporter.verify();

    return res.json({
      success: true,
      message: "SMTP verified successfully"
    });
  } catch (error) {
    console.error("SMTP Verify Error:", error.message);
    return res.status(401).json({
      success: false,
      message: error.message || "SMTP Authentication failed"
    });
  }
});

/* ---------------- SEND BATCH (ALL EMAILS SEND) ---------------- */

app.post("/api/send-batch", async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipients } = req.body;

  if (!email || !appPassword || !Array.isArray(recipients) || recipients.length === 0) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields or recipients list is empty"
    });
  }

  if (globalStop) {
    return res.status(400).json({
      success: false,
      message: "Process currently stopped"
    });
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || "").replace(/["\r\n]/g, "").trim();
  const transporter = getTransporter(email, appPassword);

  const isHtml = /<[a-z][\s\S]*>/i.test(messageBody || "");
  const formattedHtml = isHtml 
    ? messageBody 
    : `<div dir="ltr" style="font-family: Arial, Helvetica, sans-serif; font-size: 14px; color: #222; line-height: 1.5; margin-top: 16px;">${(messageBody || "").replace(/\n/g, "<br>")}</div>`;
  
  const plainText = (messageBody || "").replace(/<[^>]+>/g, "").trim();

  // Send all recipients in parallel without restricting batch limit
  const results = await Promise.allSettled(
    recipients.map(async (recipient) => {
      const targetEmail = typeof recipient === 'object' ? (recipient.email || recipient.recipient) : String(recipient);
      const cleanTarget = (targetEmail || "").trim();

      if (!cleanTarget) {
        return { success: false, recipient: cleanTarget, error: "Invalid Email" };
      }

      try {
        await transporter.sendMail({
          from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
          to: cleanTarget,
          replyTo: cleanEmail,
          date: new Date(),
          subject: subject || "No Subject",
          text: plainText,
          html: formattedHtml,
          textEncoding: 'quoted-printable',
          encoding: 'utf-8'
        });

        return { success: true, recipient: cleanTarget };
      } catch (error) {
        console.error("Email send failed for:", cleanTarget, error.message);
        return { success: false, recipient: cleanTarget, error: error.message };
      }
    })
  );

  let sent = 0;
  let failed = 0;
  const details = [];

  for (const r of results) {
    if (r.status === "fulfilled" && r.value.success) {
      sent++;
      details.push(r.value);
    } else {
      failed++;
      details.push(r.status === "fulfilled" ? r.value : { success: false, error: r.reason?.message });
    }
  }

  return res.json({
    success: true,
    results: { sent, failed, details }
  });
});

/* ---------------- STOP PROCESS ---------------- */

app.post("/api/stop", (req, res) => {
  globalStop = true;
  res.json({ success: true, message: "Process stopped." });

  setTimeout(() => {
    globalStop = false;
  }, 4000);
});

/* ---------------- START SERVER ---------------- */

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});

export default app;

const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Delay helper function
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Status check route
app.get("/api/health", (req, res) => {
  res.json({ status: "running", proxyConfigured: Boolean(process.env.PROXY_URL) });
});

// Bulk send API endpoint
app.post("/api/send-batch", async (req, res) => {
  const { senderEmail, appPassword, recipients, subject, bodyText, senderName } = req.body;

  if (!senderEmail || !appPassword) {
    return res.status(400).json({ error: "Sender email aur app password zaroori hain." });
  }

  if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
    return res.status(400).json({ error: "Recipients ki list honi chahiye." });
  }

  // Vercel Environment Variable se Proxy uthayega
  const proxyUrl = process.env.PROXY_URL;
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

  // Gmail SMTP Transporter
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: senderEmail,
      pass: appPassword,
    },
    ...(agent && {
      agent: agent,
      proxy: proxyUrl,
    }),
    pool: true,
    maxConnections: 1,
    rateLimit: 6,
    rateDelta: 20000,
  });

  const results = [];
  const BATCH_SIZE = 6;
  const currentBatch = recipients.slice(0, BATCH_SIZE);

  for (let i = 0; i < currentBatch.length; i++) {
    const targetEmail = currentBatch[i].trim();

    try {
      // Dynamic clean headers taaki spam filter trigger na ho
      const info = await transporter.sendMail({
        from: `"${senderName || "Support"}" <${senderEmail}>`,
        to: targetEmail,
        subject: subject,
        text: bodyText,
        headers: {
          "X-Priority": "3",
          "X-Mailer": "Microsoft Office 365",
          "Message-ID": `<${Date.now()}.${Math.random().toString(36).substring(2, 9)}@gmail.com>`,
        },
      });

      results.push({ email: targetEmail, status: "Sent", id: info.messageId });

      // Har mail ke beech 2.5 second ka safe pause
      if (i < currentBatch.length - 1) {
        await sleep(2500);
      }
    } catch (err) {
      results.push({ email: targetEmail, status: "Failed", error: err.message });
    }
  }

  return res.json({
    success: true,
    totalSent: results.filter((r) => r.status === "Sent").length,
    batchResults: results,
  });
});

// Vercel export aur local port listening
if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => {
    console.log(`Server chal raha hai port ${PORT} par`);
  });
}

module.exports = app;

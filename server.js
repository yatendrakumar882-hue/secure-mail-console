const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname)));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Homepage Load Route (Isse "Cannot GET /" theek ho jayega)
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, "index.html"), (err2) => {
        if (err2) {
          res.send("<h2>Console Backend Active. API Endpoint: /api/send-batch</h2>");
        }
      });
    }
  });
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

  const proxyUrl = process.env.PROXY_URL;
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

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

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;

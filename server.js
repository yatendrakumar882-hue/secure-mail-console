const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname)));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Authentication Route
const APP_PASSWORD_KEY = process.env.ACCESS_PASSWORD || "@##";
app.post(["/api/login", "/api/auth", "/login", "/auth"], (req, res) => {
  const { password } = req.body;
  if (password === APP_PASSWORD_KEY) {
    return res.json({ success: true, token: "authorized_session_token" });
  }
  return res.status(401).json({ success: false, message: "Invalid password" });
});

// Helper: Build Safe Transporter
function createGmailTransporter(user, pass) {
  const proxyUrl = process.env.PROXY_URL;
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: user.trim(),
      pass: pass.trim().replace(/\s+/g, ""),
    },
    ...(agent && {
      agent: agent,
      proxy: proxyUrl,
    }),
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
    pool: true,
    maxConnections: 1,
    rateLimit: 6,
    rateDelta: 15000,
  });
}

// Fallback Transporter (Direct Connection if Proxy Stalls)
function createDirectTransporter(user, pass) {
  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: user.trim(),
      pass: pass.trim().replace(/\s+/g, ""),
    },
    connectionTimeout: 10000,
  });
}

// Main Send Engine (Streaming + JSON Fallback)
app.all(
  ["/api/send-stream", "/api/send", "/api/send-batch", "/send", "/send-stream"],
  async (req, res) => {
    const payload = req.method === "POST" ? req.body : req.query;
    const {
      senderEmail,
      appPassword,
      recipients,
      to,
      subject,
      bodyText,
      message,
      htmlContent,
      senderName,
    } = payload;

    let targetList = [];
    if (Array.isArray(recipients)) {
      targetList = recipients;
    } else if (typeof recipients === "string") {
      targetList = recipients.split(/[\n,]+/).map((e) => e.trim()).filter(Boolean);
    } else if (to) {
      targetList = Array.isArray(to) ? to : [to];
    }

    if (!senderEmail || !appPassword) {
      return res.status(400).json({ error: "Sender email & App Password required." });
    }

    if (!targetList || targetList.length === 0) {
      return res.status(400).json({ error: "No recipients provided." });
    }

    // Initialize SSE Headers so frontend stream doesn't throw error
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });

    const sendSSE = (event, data) => {
      res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    };

    sendSSE("start", { total: targetList.length });

    let transporter = createGmailTransporter(senderEmail, appPassword);
    const BATCH_SIZE = 6;

    for (let i = 0; i < targetList.length; i++) {
      const email = targetList[i].trim();
      if (!email) continue;

      let emailSent = false;

      // Clean Anti-Spam Headers
      const mailOptions = {
        from: `"${senderName || "Help Desk"}" <${senderEmail.trim()}>`,
        to: email,
        subject: subject || "Quick Update",
        text: bodyText || message || "Please check your document update.",
        ...(htmlContent && { html: htmlContent }),
        headers: {
          "X-Priority": "3",
          "X-Mailer": "Microsoft Office 365",
          "Message-ID": `<${Date.now()}.${Math.random().toString(36).substring(2, 9)}@gmail.com>`,
        },
      };

      // Try sending via Proxy first
      try {
        const info = await transporter.sendMail(mailOptions);
        sendSSE("sent", { email, status: "Sent", id: info.messageId, index: i + 1 });
        emailSent = true;
      } catch (proxyErr) {
        // Fallback to direct SMTP if proxy handshake timed out
        try {
          const directTransporter = createDirectTransporter(senderEmail, appPassword);
          const fallbackInfo = await directTransporter.sendMail(mailOptions);
          sendSSE("sent", { email, status: "Sent", id: fallbackInfo.messageId, index: i + 1 });
          emailSent = true;
        } catch (directErr) {
          sendSSE("failed", { email, error: directErr.message, index: i + 1 });
        }
      }

      // Safe pacing: 1.8s per email, plus extra pause after 6 emails
      if ((i + 1) % BATCH_SIZE === 0 && i < targetList.length - 1) {
        await sleep(3500);
      } else if (i < targetList.length - 1) {
        await sleep(1800);
      }
    }

    sendSSE("complete", { status: "All emails processed." });
    res.end();
  }
);

// Fallback to UI file
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"), (err) => {
    if (err) {
      res.sendFile(path.join(__dirname, "index.html"), (err2) => {
        if (err2) {
          res.send("<h2>Console Backend Active. index.html not found.</h2>");
        }
      });
    }
  });
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}

module.exports = app;

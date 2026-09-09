const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function sanitizeEmail(str) {
  if (!str) return "";
  return str
    .trim()
    .replace(/^[^a-zA-Z0-9]+/, "")
    .replace(/@gnoil\.com$/i, "@gmail.com")
    .replace(/@gmai1\.com$/i, "@gmail.com")
    .replace(/@gmail\.c$/i, "@gmail.com");
}

// 1. Password Verification (@##)
app.post(["/api/login", "/api/auth", "/login"], (req, res) => {
  const { password } = req.body;
  if (password === "@##") {
    return res.json({ success: true });
  }
  return res.status(401).json({ success: false });
});

// 2. Transporter Generator - Force New IP per connection
function createFreshTransporter(user, pass) {
  let proxyUrl = process.env.PROXY_URL;
  let agent = null;

  if (proxyUrl) {
    // Session timestamp randomize karte hain taaki ipPeak har mail par nayi residential IP assign kare
    const randomSessionId = Math.floor(10000000 + Math.random() * 90000000);
    let dynamicProxyUrl = proxyUrl;

    if (proxyUrl.includes("session-")) {
      dynamicProxyUrl = proxyUrl.replace(/session-[0-9a-zA-Z]+/, `session-${randomSessionId}`);
    } else if (proxyUrl.includes("-zone-")) {
      // Rotating URL format
      dynamicProxyUrl = proxyUrl.replace("@", `-session-${randomSessionId}@`);
    }

    agent = new HttpsProxyAgent(dynamicProxyUrl);
  }

  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: sanitizeEmail(user),
      pass: pass.trim().replace(/\s+/g, ""),
    },
    ...(agent && {
      agent: agent,
    }),
    pool: false, // Connection reuse band taaki nayi IP force ho
    connectionTimeout: 9000,
    greetingTimeout: 9000,
    socketTimeout: 9000,
  });
}

// 3. Batch Sending Engine (6 Emails with Rotating IPs)
app.post(["/api/send-batch", "/api/send-stream", "/api/send", "/send"], async (req, res) => {
  let { senderEmail, appPassword, recipients, to, subject, bodyText, senderName } = req.body;

  let rawList = recipients || to || [];
  let list = Array.isArray(rawList) ? rawList : String(rawList).split(/[\r\n,;]+/);
  let validRecipients = list.map(sanitizeEmail).filter((e) => e && e.includes("@"));

  if (!senderEmail || !appPassword || validRecipients.length === 0) {
    return res.status(400).json({ error: "Details khali hain ya email galat hai." });
  }

  const currentBatch = validRecipients.slice(0, 6);
  const results = [];

  for (let i = 0; i < currentBatch.length; i++) {
    const target = currentBatch[i];

    // Har email ke liye bilkul fresh transporter (Nayi IP)
    const transporter = createFreshTransporter(senderEmail, appPassword);

    const randomMsgId = `${Date.now()}.${Math.random().toString(36).substring(2, 8)}@mail.gmail.com`;

    const mailOptions = {
      from: `"${senderName || "Document Support"}" <${sanitizeEmail(senderEmail)}>`,
      to: target,
      subject: subject || "Important Account Notice",
      text: bodyText || "Please find the requested document update attached.",
      headers: {
        "X-Priority": "3",
        "X-MSMail-Priority": "Normal",
        "Importance": "Normal",
        "X-Mailer": "Microsoft Outlook 16.0",
        "Message-ID": `<${randomMsgId}>`,
        "MIME-Version": "1.0",
        "Content-Language": "en-US",
      },
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      results.push({ email: target, status: "Sent", id: info.messageId });
    } catch (err) {
      // Fallback direct attempt if proxy connection slows down
      try {
        const directTransporter = nodemailer.createTransport({
          host: "smtp.gmail.com",
          port: 465,
          secure: true,
          auth: {
            user: sanitizeEmail(senderEmail),
            pass: appPassword.trim().replace(/\s+/g, ""),
          },
          pool: false,
          connectionTimeout: 8000,
        });
        const info = await directTransporter.sendMail(mailOptions);
        results.push({ email: target, status: "Sent", id: info.messageId });
      } catch (fallbackErr) {
        results.push({ email: target, status: "Failed", error: fallbackErr.message });
      }
    }

    // Natural human gap between emails (1.2 seconds)
    if (i < currentBatch.length - 1) {
      await sleep(1200);
    }
  }

  return res.json({
    success: true,
    sentCount: results.filter((r) => r.status === "Sent").length,
    failedCount: results.filter((r) => r.status === "Failed").length,
    results,
  });
});

// UI Delivery
app.get("*", (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Bulk Email Console</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; font-family: sans-serif; }
    body { background: #0f172a; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
    .box { background: #1e293b; padding: 25px; border-radius: 12px; width: 100%; max-width: 800px; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }
    h2 { color: #38bdf8; margin-top: 0; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px; }
    label { font-size: 13px; color: #94a3b8; display: block; margin-bottom: 5px; }
    input, textarea { width: 100%; padding: 10px; background: #0b1329; border: 1px solid #334155; border-radius: 6px; color: #fff; font-size: 14px; }
    textarea { height: 110px; }
    button { width: 100%; padding: 12px; background: #2563eb; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 15px; margin-top: 10px; }
    button:hover { background: #1d4ed8; }
    button:disabled { background: #64748b; cursor: not-allowed; }
    .stats { display: flex; justify-content: space-around; background: #0b1329; padding: 15px; border-radius: 8px; margin-top: 15px; text-align: center; }
    .stat-val { font-size: 22px; font-weight: bold; }
    #logBox { background: #050b14; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; max-height: 140px; overflow-y: auto; margin-top: 15px; color: #38bdf8; }
    .hidden { display: none !important; }
  </style>
</head>
<body>
  <div id="authPanel" class="box" style="max-width: 400px; text-align: center;">
    <h2>Access Protected</h2>
    <p style="color: #94a3b8; font-size: 13px;">Enter password to continue</p>
    <input type="password" id="sysPass" placeholder="Password (@##)" style="margin-bottom: 12px;" />
    <button onclick="login()">Enter Console</button>
    <p id="authErr" style="color: #ef4444; font-size: 13px; margin-top: 10px; display: none;">Invalid Password</p>
  </div>

  <div id="mailPanel" class="box hidden">
    <h2>Bulk Email Sender (Rotating IP Engine)</h2>
    <div class="grid">
      <div><label>Sender Name</label><input id="sName" value="Warren Support" /></div>
      <div><label>Your Gmail</label><input id="sEmail" placeholder="yourname@gmail.com" /></div>
    </div>
    <div class="grid">
      <div><label>App Password (16 Letters)</label><input type="password" id="sPass" placeholder="abcd efgh ijkl mnop" /></div>
      <div><label>Email Subject</label><input id="sSub" value="Project Invoice Update #8942" /></div>
    </div>
    <div class="grid">
      <div><label>Message Body</label><textarea id="sBody">Hello, please find the updated document statement attached for your reference. Let us know if you need anything else.</textarea></div>
      <div><label>Recipients (6 per batch)</label><textarea id="sRecipients" placeholder="client1@gmail.com&#10;client2@gmail.com"></textarea></div>
    </div>
    
    <button id="sendBtn" onclick="sendBatch()">Send 6 Emails Batch (Rotating IP)</button>

    <div class="stats">
      <div><div class="stat-val" id="cntTotal">0</div><span style="color:#64748b; font-size:12px;">TOTAL</span></div>
      <div><div class="stat-val" id="cntSent" style="color:#22c55e;">0</div><span style="color:#64748b; font-size:12px;">SENT</span></div>
      <div><div class="stat-val" id="cntFail" style="color:#ef4444;">0</div><span style="color:#64748b; font-size:12px;">FAILED</span></div>
    </div>

    <div id="logBox">System Ready. New IP assigned per mail.</div>
  </div>

  <script>
    async function login() {
      const p = document.getElementById("sysPass").value;
      if (p === "@##") {
        document.getElementById("authPanel").classList.add("hidden");
        document.getElementById("mailPanel").classList.remove("hidden");
      } else {
        document.getElementById("authErr").style.display = "block";
      }
    }

    async function sendBatch() {
      const btn = document.getElementById("sendBtn");
      const log = document.getElementById("logBox");
      const sEmail = document.getElementById("sEmail").value.trim();
      const sPass = document.getElementById("sPass").value.trim();
      const sRecipients = document.getElementById("sRecipients").value.trim();
      const sSub = document.getElementById("sSub").value;
      const sBody = document.getElementById("sBody").value;
      const sName = document.getElementById("sName").value;

      if (!sEmail || !sPass || !sRecipients) {
        alert("Please fill all details.");
        return;
      }

      btn.disabled = true;
      btn.innerText = "Dispatching with IP rotation...";
      log.innerText = "Generating dynamic residential IPs & sending...";

      try {
        const res = await fetch("/api/send-batch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            senderEmail: sEmail,
            appPassword: sPass,
            recipients: sRecipients,
            subject: sSub,
            bodyText: sBody,
            senderName: sName
          })
        });

        const data = await res.json();
        if (data.success) {
          document.getElementById("cntTotal").innerText = data.results.length;
          document.getElementById("cntSent").innerText = data.sentCount;
          document.getElementById("cntFail").innerText = data.failedCount;

          let details = data.results.map(r => r.email + " -> " + r.status).join("\\n");
          log.innerText = "Dispatch Completed!\\n" + details;
          alert("Success! Sent: " + data.sentCount);
        } else {
          log.innerText = "Error: " + (data.error || "Failed");
          alert("Error: " + data.error);
        }
      } catch (err) {
        log.innerText = "Network Error: " + err.message;
        alert("Dispatch error occurred.");
      } finally {
        btn.disabled = false;
        btn.innerText = "Send 6 Emails Batch (Rotating IP)";
      }
    }
  </script>
</body>
</html>`);
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`Running on ${PORT}`));
}

module.exports = app;

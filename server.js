const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const https = require("https");

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 🛡️ INBOX DELIVERABILITY SPEED CONTROLS
// ==========================================
const BLITZ_SIZE = 2;          // 2 emails per blitz (Optimal for spam avoidance)
const DELAY_BETWEEN_EMAILS = 1200; // 1.2s gap between each email
const BLITZ_COOLDOWN = 2500;   // 2.5s cooldown between blitzes
// ==========================================

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));

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

// 1. Password Route (@##)
app.post(["/api/login", "/api/auth", "/login"], (req, res) => {
  const { password } = req.body;
  if (password === "@##") return res.json({ success: true });
  return res.status(401).json({ success: false });
});

// Helper: Check Proxy IP
function getProxyIP(agent) {
  return new Promise((resolve) => {
    if (!agent) return resolve("Direct IP");
    const req = https.get("https://api.ipify.org?format=json", { agent, timeout: 4000 }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => {
        try { resolve(JSON.parse(data).ip || "Proxy Active"); } catch (e) { resolve("Proxy Active"); }
      });
    });
    req.on("error", () => resolve("Proxy Active"));
    req.on("timeout", () => { req.destroy(); resolve("Proxy Active"); });
  });
}

// 2. Transporter Generator
function createStickyTransporter(user, pass) {
  const proxyUrl = process.env.PROXY_URL;
  const agent = proxyUrl ? new HttpsProxyAgent(proxyUrl) : null;

  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: sanitizeEmail(user),
      pass: pass.trim().replace(/\s+/g, ""),
    },
    ...(agent && { agent }),
    pool: true,
    maxConnections: 1,
    connectionTimeout: 9000,
    greetingTimeout: 9000,
    socketTimeout: 9000,
  });

  return { transporter, agent };
}

// 3. Optimized Batch Dispatch Route
app.post("/api/send-chunk", async (req, res) => {
  let { senderEmail, appPassword, chunk, subject, bodyText, senderName } = req.body;

  if (!senderEmail || !appPassword || !chunk || !Array.isArray(chunk) || chunk.length === 0) {
    return res.status(400).json({ error: "Missing required details." });
  }

  const safeChunk = chunk.slice(0, BLITZ_SIZE);
  const { transporter, agent } = createStickyTransporter(senderEmail, appPassword);
  const usedIP = await getProxyIP(agent);
  const results = [];

  for (let i = 0; i < safeChunk.length; i++) {
    const rawTarget = safeChunk[i];
    const target = sanitizeEmail(rawTarget);

    if (!target || !target.includes("@")) {
      results.push({ email: rawTarget, status: "Invalid Email" });
      continue;
    }

    // RFC Standard Dynamic Message-ID
    const uniqueDomain = senderEmail.split("@")[1] || "gmail.com";
    const cleanMsgId = `${Date.now()}.${Math.random().toString(36).substring(2, 8)}@${uniqueDomain}`;

    const mailOptions = {
      from: `"${senderName || "Support"}" <${sanitizeEmail(senderEmail)}>`,
      to: target,
      subject: subject || "Account Notification",
      text: bodyText || "Please review the communication update attached.",
      headers: {
        "X-Priority": "3",
        "X-MSMail-Priority": "Normal",
        "Importance": "Normal",
        "X-Mailer": "Microsoft Outlook 16.0",
        "Message-ID": `<${cleanMsgId}>`,
        "Date": new Date().toUTCString(),
        "MIME-Version": "1.0",
        "Content-Language": "en-US",
      },
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      results.push({ email: target, status: "Sent", ip: usedIP, id: info.messageId });
    } catch (err) {
      try {
        const directTransporter = nodemailer.createTransport({
          host: "smtp.gmail.com",
          port: 465,
          secure: true,
          auth: { user: sanitizeEmail(senderEmail), pass: appPassword.trim().replace(/\s+/g, "") },
          connectionTimeout: 6000,
        });
        const info = await directTransporter.sendMail(mailOptions);
        results.push({ email: target, status: "Sent", ip: "Fallback Direct", id: info.messageId });
      } catch (fallbackErr) {
        results.push({ email: target, status: "Failed", ip: usedIP, error: fallbackErr.message });
      }
    }

    if (i < safeChunk.length - 1) {
      await sleep(DELAY_BETWEEN_EMAILS);
    }
  }

  return res.json({
    success: true,
    sentCount: results.filter((r) => r.status === "Sent").length,
    failedCount: results.filter((r) => r.status === "Failed").length,
    results,
  });
});

// 4. Clean White Console UI
app.get("*", (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Bulk Email Console</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: #f8fafc; color: #1e293b; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
    .box { background: #ffffff; border: 1px solid #e2e8f0; padding: 25px; border-radius: 12px; width: 100%; max-width: 820px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); }
    h2 { color: #0284c7; margin-top: 0; display: flex; align-items: center; justify-content: space-between; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px; }
    label { font-size: 13px; color: #64748b; font-weight: 600; display: block; margin-bottom: 5px; }
    input, textarea { width: 100%; padding: 10px; background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; color: #0f172a; font-size: 14px; }
    textarea { height: 100px; resize: none; }
    input:focus, textarea:focus { outline: none; border-color: #0284c7; background: #fff; }
    .send-btn { width: 100%; padding: 13px; background: #0284c7; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 15px; margin-top: 10px; transition: 0.2s; }
    .send-btn:hover { background: #0369a1; }
    .send-btn:disabled { background: #94a3b8; cursor: not-allowed; }
    .logout-btn { background: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: bold; cursor: pointer; }
    .logout-btn:hover { background: #dc2626; }
    .stats { display: flex; justify-content: space-around; background: #f1f5f9; padding: 15px; border-radius: 8px; margin-top: 15px; text-align: center; border: 1px solid #e2e8f0; }
    .stat-val { font-size: 22px; font-weight: bold; }
    #logBox { background: #0f172a; color: #38bdf8; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; max-height: 150px; overflow-y: auto; margin-top: 15px; }
    .hidden { display: none !important; }
    .badge { background: #e0f2fe; color: #0284c7; padding: 3px 8px; border-radius: 4px; font-size: 12px; }
  </style>
</head>
<body>

  <div id="authPanel" class="box" style="max-width: 400px; text-align: center;">
    <h2>Access Protected</h2>
    <p style="color: #64748b; font-size: 13px;">Enter password to continue</p>
    <input type="password" id="sysPass" placeholder="Password (@##)" style="margin-bottom: 12px;" />
    <button class="send-btn" onclick="login()">Enter Console</button>
    <p id="authErr" style="color: #ef4444; font-size: 13px; margin-top: 10px; display: none;">Invalid Password</p>
  </div>

  <div id="mailPanel" class="box hidden">
    <h2>
      <div>Bulk Email Sender <span class="badge">Safe Blitz Delivery</span></div>
      <button class="logout-btn" title="Double click to logout" ondblclick="performLogout()">Logout (Double Click)</button>
    </h2>

    <div class="grid">
      <div><label>Sender Name</label><input id="sName" value="Warren Support" /></div>
      <div><label>Your Gmail</label><input id="sEmail" placeholder="yourname@gmail.com" /></div>
    </div>
    <div class="grid">
      <div><label>App Password (16 Letters)</label><input type="password" id="sPass" placeholder="abcd efgh ijkl mnop" /></div>
      <div><label>Email Subject</label><input id="sSub" value="Project Invoice Update #8942" /></div>
    </div>
    <div class="grid">
      <div><label>Message Body</label><textarea id="sBody">Hello, please find the required details attached for your review. Let us know if you have questions.</textarea></div>
      <div><label>Recipients (Paste all emails)</label><textarea id="sRecipients" placeholder="client1@gmail.com&#10;client2@gmail.com"></textarea></div>
    </div>
    
    <button class="send-btn" id="sendBtn" onclick="startAutoBatchDispatch()">Send All Emails (Inbox Safe Mode)</button>

    <div class="stats">
      <div><div class="stat-val" id="cntTotal">0</div><span style="color:#64748b; font-size:12px;">TOTAL</span></div>
      <div><div class="stat-val" id="cntSent" style="color:#16a34a;">0</div><span style="color:#64748b; font-size:12px;">SENT</span></div>
      <div><div class="stat-val" id="cntFail" style="color:#dc2626;">0</div><span style="color:#64748b; font-size:12px;">FAILED</span></div>
      <div><div class="stat-val" id="cntRemaining" style="color:#ca8a04;">0</div><span style="color:#64748b; font-size:12px;">REMAINING</span></div>
    </div>

    <div id="logBox">System Ready. Safe 2/Blitz mode active with human pacing.</div>
  </div>

  <script>
    const BATCH_SIZE = ${BLITZ_SIZE};
    const PAUSE_TIME = ${BLITZ_COOLDOWN};

    function login() {
      if (document.getElementById("sysPass").value === "@##") {
        document.getElementById("authPanel").classList.add("hidden");
        document.getElementById("mailPanel").classList.remove("hidden");
      } else {
        document.getElementById("authErr").style.display = "block";
      }
    }

    function performLogout() {
      document.getElementById("sysPass").value = "";
      document.getElementById("mailPanel").classList.add("hidden");
      document.getElementById("authPanel").classList.remove("hidden");
      alert("Logged out successfully.");
    }

    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    async function startAutoBatchDispatch() {
      const btn = document.getElementById("sendBtn");
      const log = document.getElementById("logBox");
      const sEmail = document.getElementById("sEmail").value.trim();
      const sPass = document.getElementById("sPass").value.trim();
      const rawRecipients = document.getElementById("sRecipients").value.trim();
      const sSub = document.getElementById("sSub").value;
      const sBody = document.getElementById("sBody").value;
      const sName = document.getElementById("sName").value;

      if (!sEmail || !sPass || !rawRecipients) {
        alert("Please fill Gmail, App Password, and Recipients!");
        return;
      }

      const allEmails = rawRecipients.split(/[\\r\\n,;]+/).map(e => e.trim().replace(/^[^a-zA-Z0-9]+/, "")).filter(e => e && e.includes("@"));
      if (allEmails.length === 0) return alert("No valid recipients!");

      const batches = [];
      for (let i = 0; i < allEmails.length; i += BATCH_SIZE) {
        batches.push(allEmails.slice(i, i + BATCH_SIZE));
      }

      let totalSent = 0;
      let totalFailed = 0;
      document.getElementById("cntTotal").innerText = allEmails.length;
      document.getElementById("cntSent").innerText = 0;
      document.getElementById("cntFail").innerText = 0;
      document.getElementById("cntRemaining").innerText = allEmails.length;

      btn.disabled = true;
      log.innerText = "Dispatching in safe batches of " + BATCH_SIZE + "...\\n";

      for (let bIndex = 0; bIndex < batches.length; bIndex++) {
        const currentBatch = batches[bIndex];
        btn.innerText = "Sending Blitz " + (bIndex + 1) + "/" + batches.length + "...";
        log.innerText += "\\n--- Blitz " + (bIndex + 1) + "/" + batches.length + " (" + currentBatch.length + " Emails) ---\\n";

        try {
          const res = await fetch("/api/send-chunk", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ senderEmail: sEmail, appPassword: sPass, chunk: currentBatch, subject: sSub, bodyText: sBody, senderName: sName })
          });
          const data = await res.json();
          if (data.success) {
            totalSent += data.sentCount;
            totalFailed += data.failedCount;
            document.getElementById("cntSent").innerText = totalSent;
            document.getElementById("cntFail").innerText = totalFailed;
            document.getElementById("cntRemaining").innerText = allEmails.length - (totalSent + totalFailed);
            data.results.forEach(r => log.innerText += r.email + " -> " + r.status + " [IP: " + (r.ip || "Sticky") + "]\\n");
          } else {
            totalFailed += currentBatch.length;
            document.getElementById("cntFail").innerText = totalFailed;
          }
        } catch (e) {
          totalFailed += currentBatch.length;
          document.getElementById("cntFail").innerText = totalFailed;
        }
        log.scrollTop = log.scrollHeight;
        if (bIndex < batches.length - 1) await sleep(PAUSE_TIME);
      }

      btn.disabled = false;
      btn.innerText = "Send All Emails (Inbox Safe Mode)";
      log.innerText += "\\n=== ALL DISPATCHED ===";
      log.scrollTop = log.scrollHeight;
      alert("Completed! Sent: " + totalSent + ", Failed: " + totalFailed);
    }
  </script>
</body>
</html>`);
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`Running on ${PORT}`));
}

module.exports = app;

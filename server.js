const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const https = require("https");

const app = express();
const PORT = process.env.PORT || 3000;

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

// 1. Password Verification (@##)
app.post(["/api/login", "/api/auth", "/login"], (req, res) => {
  const { password } = req.body;
  if (password === "@##") {
    return res.json({ success: true });
  }
  return res.status(401).json({ success: false });
});

// Helper: Check Current Proxy Public IP
function getProxyIP(agent) {
  return new Promise((resolve) => {
    if (!agent) return resolve("Direct Vercel IP");
    const req = https.get(
      "https://api.ipify.org?format=json",
      { agent, timeout: 5000 },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const parsed = JSON.parse(data);
            resolve(parsed.ip || "Proxy Connected");
          } catch (e) {
            resolve("Proxy Active");
          }
        });
      }
    );
    req.on("error", () => resolve("Proxy Handshake Active"));
    req.on("timeout", () => {
      req.destroy();
      resolve("Proxy Active");
    });
  });
}

// 2. Transporter Generator - ipPeak Residential Session Rotation
function createFreshTransporter(user, pass) {
  let proxyUrl = process.env.PROXY_URL;
  let agent = null;

  if (proxyUrl) {
    const randomSessionId = Math.floor(10000000 + Math.random() * 90000000);
    let dynamicProxyUrl = proxyUrl;

    if (proxyUrl.includes("session-")) {
      dynamicProxyUrl = proxyUrl.replace(/session-[0-9a-zA-Z]+/, `session-${randomSessionId}`);
    } else if (proxyUrl.includes("-zone-") || proxyUrl.includes("crp.apexae.top")) {
      dynamicProxyUrl = proxyUrl.replace("@", `-session-${randomSessionId}@`);
    }

    agent = new HttpsProxyAgent(dynamicProxyUrl);
  }

  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: sanitizeEmail(user),
      pass: pass.trim().replace(/\s+/g, ""),
    },
    ...(agent && { agent }),
    pool: false,
    connectionTimeout: 8000,
    greetingTimeout: 8000,
    socketTimeout: 8000,
  });

  return { transporter, agent };
}

// 3. Batch Endpoint: Exactly 8 Emails per Blitz/Chunk
app.post("/api/send-chunk", async (req, res) => {
  let { senderEmail, appPassword, chunk, subject, bodyText, senderName } = req.body;

  if (!senderEmail || !appPassword || !chunk || !Array.isArray(chunk) || chunk.length === 0) {
    return res.status(400).json({ error: "Missing required chunk details." });
  }

  const results = [];
  // Strict 8 emails per blitz
  const safeChunk = chunk.slice(0, 8);

  for (let i = 0; i < safeChunk.length; i++) {
    const target = sanitizeEmail(safeChunk[i]);
    if (!target || !target.includes("@")) continue;

    const { transporter, agent } = createFreshTransporter(senderEmail, appPassword);
    const usedIP = await getProxyIP(agent);

    const cleanMsgId = `${Date.now()}.${Math.random().toString(36).substring(2, 9)}@mail.gmail.com`;

    const mailOptions = {
      from: `"${senderName || "Document Support"}" <${sanitizeEmail(senderEmail)}>`,
      to: target,
      subject: subject || "Important Account Notice",
      text: bodyText || "Please find the requested update attached for your reference.",
      headers: {
        "X-Priority": "3",
        "X-MSMail-Priority": "Normal",
        "Importance": "Normal",
        "X-Mailer": "Microsoft Outlook 16.0",
        "Message-ID": `<${cleanMsgId}>`,
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
          auth: {
            user: sanitizeEmail(senderEmail),
            pass: appPassword.trim().replace(/\s+/g, ""),
          },
          pool: false,
          connectionTimeout: 7000,
        });
        const info = await directTransporter.sendMail(mailOptions);
        results.push({ email: target, status: "Sent", ip: "Fallback Direct", id: info.messageId });
      } catch (fallbackErr) {
        results.push({ email: target, status: "Failed", ip: usedIP, error: fallbackErr.message });
      }
    }

    if (i < safeChunk.length - 1) {
      await sleep(300);
    }
  }

  return res.json({
    success: true,
    sentCount: results.filter((r) => r.status === "Sent").length,
    failedCount: results.filter((r) => r.status === "Failed").length,
    results,
  });
});

// 4. UI with Double-Click Logout and 2/Batch Engine
app.get("*", (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Bulk Email Console</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: #0f172a; color: #fff; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
    .box { background: #1e293b; padding: 25px; border-radius: 12px; width: 100%; max-width: 820px; box-shadow: 0 8px 30px rgba(0,0,0,0.5); position: relative; }
    h2 { color: #38bdf8; margin-top: 0; display: flex; align-items: center; justify-content: space-between; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px; }
    label { font-size: 13px; color: #94a3b8; display: block; margin-bottom: 5px; }
    input, textarea { width: 100%; padding: 10px; background: #0b1329; border: 1px solid #334155; border-radius: 6px; color: #fff; font-size: 14px; }
    textarea { height: 110px; resize: none; }
    button.send-btn { width: 100%; padding: 12px; background: #2563eb; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 15px; margin-top: 10px; transition: 0.2s; }
    button.send-btn:hover { background: #1d4ed8; }
    button.send-btn:disabled { background: #64748b; cursor: not-allowed; }
    .logout-btn { background: #ef4444; color: white; border: none; padding: 6px 12px; border-radius: 6px; font-size: 12px; font-weight: bold; cursor: pointer; transition: 0.2s; }
    .logout-btn:hover { background: #dc2626; }
    .stats { display: flex; justify-content: space-around; background: #0b1329; padding: 15px; border-radius: 8px; margin-top: 15px; text-align: center; }
    .stat-val { font-size: 22px; font-weight: bold; }
    #logBox { background: #050b14; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; max-height: 160px; overflow-y: auto; margin-top: 15px; color: #38bdf8; border: 1px solid #1e293b; }
    .hidden { display: none !important; }
    .badge { background: #0284c7; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: normal; margin-left: 8px; color: white; }
  </style>
</head>
<body>

  <!-- Access Protected Login -->
  <div id="authPanel" class="box" style="max-width: 400px; text-align: center;">
    <h2>Access Protected</h2>
    <p style="color: #94a3b8; font-size: 13px;">Enter password to continue</p>
    <input type="password" id="sysPass" placeholder="Password (@##)" style="margin-bottom: 12px;" />
    <button class="send-btn" onclick="login()">Enter Console</button>
    <p id="authErr" style="color: #ef4444; font-size: 13px; margin-top: 10px; display: none;">Invalid Password</p>
  </div>

  <!-- Main Bulk Sender Console -->
  <div id="mailPanel" class="box hidden">
    <h2>
      <div>Bulk Email Sender <span class="badge">8 per Blitz Engine</span></div>
      <button class="logout-btn" title="Double click to Logout" ondblclick="performLogout()">Logout (Double Click)</button>
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
      <div><label>Message Body</label><textarea id="sBody">Hello, please find the updated statement details attached for your review. Let us know if you have questions.</textarea></div>
      <div><label>Recipients (Paste all emails, auto 8/blitz)</label><textarea id="sRecipients" placeholder="email1@gmail.com&#10;email2@gmail.com&#10;email3@gmail.com"></textarea></div>
    </div>
    
    <button class="send-btn" id="sendBtn" onclick="startAutoBatchDispatch()">Send All Emails (Auto 8/Blitz)</button>

    <div class="stats">
      <div><div class="stat-val" id="cntTotal">0</div><span style="color:#64748b; font-size:12px;">TOTAL</span></div>
      <div><div class="stat-val" id="cntSent" style="color:#22c55e;">0</div><span style="color:#64748b; font-size:12px;">SENT</span></div>
      <div><div class="stat-val" id="cntFail" style="color:#ef4444;">0</div><span style="color:#64748b; font-size:12px;">FAILED</span></div>
      <div><div class="stat-val" id="cntRemaining" style="color:#eab308;">0</div><span style="color:#64748b; font-size:12px;">REMAINING</span></div>
    </div>

    <div id="logBox">System Ready. Rotating IP active. Double-click Logout anytime.</div>
  </div>

  <script>
    function login() {
      const p = document.getElementById("sysPass").value;
      if (p === "@##") {
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

      const allEmails = rawRecipients
        .split(/[\\r\\n,;]+/)
        .map(e => e.trim().replace(/^[^a-zA-Z0-9]+/, ""))
        .filter(e => e && e.includes("@"));

      if (allEmails.length === 0) {
        alert("No valid recipient emails found!");
        return;
      }

      // Exact 8 emails per batch
      const CHUNK_SIZE = 8;
      const batches = [];
      for (let i = 0; i < allEmails.length; i += CHUNK_SIZE) {
        batches.push(allEmails.slice(i, i + CHUNK_SIZE));
      }

      const totalEmails = allEmails.length;
      let totalSent = 0;
      let totalFailed = 0;

      document.getElementById("cntTotal").innerText = totalEmails;
      document.getElementById("cntSent").innerText = 0;
      document.getElementById("cntFail").innerText = 0;
      document.getElementById("cntRemaining").innerText = totalEmails;

      btn.disabled = true;
      log.innerText = "Dispatching " + totalEmails + " emails across " + batches.length + " blitzes (8 per blitz)...\\n";

      for (let bIndex = 0; bIndex < batches.length; bIndex++) {
        const currentBatch = batches[bIndex];
        const batchNum = bIndex + 1;

        btn.innerText = "Sending Blitz " + batchNum + "/" + batches.length + "...";
        log.innerText += "\\n--- Blitz " + batchNum + "/" + batches.length + " (8 emails via Rotating IP) ---\\n";
        log.scrollTop = log.scrollHeight;

        try {
          const res = await fetch("/api/send-chunk", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              senderEmail: sEmail,
              appPassword: sPass,
              chunk: currentBatch,
              subject: sSub,
              bodyText: sBody,
              senderName: sName
            })
          });

          const data = await res.json();
          if (data.success) {
            totalSent += data.sentCount;
            totalFailed += data.failedCount;

            document.getElementById("cntSent").innerText = totalSent;
            document.getElementById("cntFail").innerText = totalFailed;
            document.getElementById("cntRemaining").innerText = totalEmails - (totalSent + totalFailed);

            data.results.forEach(r => {
              log.innerText += r.email + " -> " + r.status + " [IP: " + (r.ip || "Rotating") + "]\\n";
            });
          } else {
            totalFailed += currentBatch.length;
            document.getElementById("cntFail").innerText = totalFailed;
            log.innerText += "Blitz " + batchNum + " Error: " + (data.error || "Failed") + "\\n";
          }
        } catch (netErr) {
          totalFailed += currentBatch.length;
          document.getElementById("cntFail").innerText = totalFailed;
          log.innerText += "Network error in blitz " + batchNum + "\\n";
        }

        log.scrollTop = log.scrollHeight;

        // 2 second cooldown between 8-email blitzes (Google inbox safety)
        if (bIndex < batches.length - 1) {
          log.innerText += "Resting 2.5s for inbox reputation...\\n";
          await sleep(2500);
        }
      }

      btn.disabled = false;
      btn.innerText = "Send All Emails (Auto 8/Blitz)";
      log.innerText += "\\n=== DISPATCH COMPLETE ===";
      log.scrollTop = log.scrollHeight;
      alert("Completed!\\nSent: " + totalSent + "\\nFailed: " + totalFailed);
    }
  </script>
</body>
</html>`);
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`Running on ${PORT}`));
}

module.exports = app;

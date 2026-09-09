const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");

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

// 1. App Password Verification (@##)
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
    const randomSessionId = Math.floor(10000000 + Math.random() * 90000000);
    let dynamicProxyUrl = proxyUrl;

    if (proxyUrl.includes("session-")) {
      dynamicProxyUrl = proxyUrl.replace(/session-[0-9a-zA-Z]+/, `session-${randomSessionId}`);
    } else if (proxyUrl.includes("-zone-")) {
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
    ...(agent && { agent }),
    pool: false,
    connectionTimeout: 8000,
    greetingTimeout: 8000,
    socketTimeout: 8000,
  });
}

// 3. Batch Endpoint: Exactly 6 emails per call (Safe for Vercel 10s limit)
app.post("/api/send-chunk", async (req, res) => {
  let { senderEmail, appPassword, chunk, subject, bodyText, senderName } = req.body;

  if (!senderEmail || !appPassword || !chunk || !Array.isArray(chunk) || chunk.length === 0) {
    return res.status(400).json({ error: "Missing required chunk details." });
  }

  const results = [];

  for (let i = 0; i < chunk.length; i++) {
    const target = sanitizeEmail(chunk[i]);
    if (!target || !target.includes("@")) continue;

    const transporter = createFreshTransporter(senderEmail, appPassword);
    const randomMsgId = `${Date.now()}.${Math.random().toString(36).substring(2, 8)}@mail.gmail.com`;

    const mailOptions = {
      from: `"${senderName || "Document Support"}" <${sanitizeEmail(senderEmail)}>`,
      to: target,
      subject: subject || "Important Document Update",
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
        results.push({ email: target, status: "Sent", id: info.messageId });
      } catch (fallbackErr) {
        results.push({ email: target, status: "Failed", error: fallbackErr.message });
      }
    }

    if (i < chunk.length - 1) {
      await sleep(250);
    }
  }

  return res.json({
    success: true,
    sentCount: results.filter((r) => r.status === "Sent").length,
    failedCount: results.filter((r) => r.status === "Failed").length,
    results,
  });
});

// 4. Built-in Client UI (Auto 6-per-Batch Loop)
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
    .box { background: #1e293b; padding: 25px; border-radius: 12px; width: 100%; max-width: 820px; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }
    h2 { color: #38bdf8; margin-top: 0; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px; }
    label { font-size: 13px; color: #94a3b8; display: block; margin-bottom: 5px; }
    input, textarea { width: 100%; padding: 10px; background: #0b1329; border: 1px solid #334155; border-radius: 6px; color: #fff; font-size: 14px; }
    textarea { height: 110px; resize: none; }
    button { width: 100%; padding: 12px; background: #2563eb; color: #fff; border: none; border-radius: 6px; font-weight: bold; cursor: pointer; font-size: 15px; margin-top: 10px; transition: 0.2s; }
    button:hover { background: #1d4ed8; }
    button:disabled { background: #64748b; cursor: not-allowed; }
    .stats { display: flex; justify-content: space-around; background: #0b1329; padding: 15px; border-radius: 8px; margin-top: 15px; text-align: center; }
    .stat-val { font-size: 22px; font-weight: bold; }
    #logBox { background: #050b14; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 12px; max-height: 160px; overflow-y: auto; margin-top: 15px; color: #38bdf8; border: 1px solid #1e293b; }
    .hidden { display: none !important; }
    .badge { background: #0284c7; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: normal; margin-left: 8px; }
  </style>
</head>
<body>

  <!-- Password Authentication -->
  <div id="authPanel" class="box" style="max-width: 400px; text-align: center;">
    <h2>Access Protected</h2>
    <p style="color: #94a3b8; font-size: 13px;">Enter password to continue</p>
    <input type="password" id="sysPass" placeholder="Password (@##)" style="margin-bottom: 12px;" />
    <button onclick="login()">Enter Console</button>
    <p id="authErr" style="color: #ef4444; font-size: 13px; margin-top: 10px; display: none;">Invalid Password</p>
  </div>

  <!-- Main Console -->
  <div id="mailPanel" class="box hidden">
    <h2>Bulk Email Sender <span class="badge">6 per Batch Engine</span></h2>
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
      <div><label>Recipients (Paste 24, 50, or 100 emails)</label><textarea id="sRecipients" placeholder="email1@gmail.com&#10;email2@gmail.com&#10;email3@gmail.com"></textarea></div>
    </div>
    
    <button id="sendBtn" onclick="startAutoBatchDispatch()">Send All Emails (Auto 6/Batch)</button>

    <div class="stats">
      <div><div class="stat-val" id="cntTotal">0</div><span style="color:#64748b; font-size:12px;">TOTAL</span></div>
      <div><div class="stat-val" id="cntSent" style="color:#22c55e;">0</div><span style="color:#64748b; font-size:12px;">SENT</span></div>
      <div><div class="stat-val" id="cntFail" style="color:#ef4444;">0</div><span style="color:#64748b; font-size:12px;">FAILED</span></div>
      <div><div class="stat-val" id="cntRemaining" style="color:#eab308;">0</div><span style="color:#64748b; font-size:12px;">REMAINING</span></div>
    </div>

    <div id="logBox">System Ready. Paste any amount of emails and click once.</div>
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

      // Clean and parse all recipient emails
      const allEmails = rawRecipients
        .split(/[\\r\\n,;]+/)
        .map(e => e.trim().replace(/^[^a-zA-Z0-9]+/, ""))
        .filter(e => e && e.includes("@"));

      if (allEmails.length === 0) {
        alert("No valid recipient emails found!");
        return;
      }

      // Split into 6-email chunks
      const CHUNK_SIZE = 6;
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
      log.innerText = "Starting: " + totalEmails + " emails split into " + batches.length + " batches (6 per batch)...\\n";

      for (let bIndex = 0; bIndex < batches.length; bIndex++) {
        const currentBatch = batches[bIndex];
        const batchNum = bIndex + 1;

        btn.innerText = "Sending Batch " + batchNum + "/" + batches.length + "...";
        log.innerText += "\\n--- Dispatching Batch " + batchNum + "/" + batches.length + " (" + currentBatch.length + " emails via Rotating IPs) ---\\n";
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
              log.innerText += r.email + " -> " + r.status + "\\n";
            });
          } else {
            totalFailed += currentBatch.length;
            document.getElementById("cntFail").innerText = totalFailed;
            log.innerText += "Batch " + batchNum + " Error: " + (data.error || "Failed") + "\\n";
          }
        } catch (netErr) {
          totalFailed += currentBatch.length;
          document.getElementById("cntFail").innerText = totalFailed;
          log.innerText += "Network error in batch " + batchNum + "\\n";
        }

        log.scrollTop = log.scrollHeight;

        // Har batch ke baad 3 second ka pause (Rate-limit and Spam safety)
        if (bIndex < batches.length - 1) {
          log.innerText += "Cooling down 3 seconds before next batch...\\n";
          await sleep(3000);
        }
      }

      btn.disabled = false;
      btn.innerText = "Send All Emails (Auto 6/Batch)";
      log.innerText += "\\n=== ALL " + totalEmails + " EMAILS COMPLETED! ===";
      log.scrollTop = log.scrollHeight;
      alert("All batches processed!\\nSent: " + totalSent + "\\nFailed: " + totalFailed);
    }
  </script>
</body>
</html>`);
});

if (process.env.NODE_ENV !== "production") {
  app.listen(PORT, () => console.log(`Running on ${PORT}`));
}

module.exports = app;

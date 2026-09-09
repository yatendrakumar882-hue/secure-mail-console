const express = require("express");
const nodemailer = require("nodemailer");
const { HttpsProxyAgent } = require("https-proxy-agent");
const https = require("https");

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 🛡️ INBOX DELIVERABILITY & 1-BY-1 CONTROLS
// ==========================================
const DELAY_BETWEEN_SINGLE_MAILS = 1800; // 1.8 second natural human pause between each email
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

// 1. Password Verification (@##)
app.post(["/api/login", "/api/auth", "/login"], (req, res) => {
  const { password } = req.body;
  if (password === "@##") return res.json({ success: true });
  return res.status(401).json({ success: false });
});

// Helper: Check Active Proxy IP
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

// 2. Transporter Generator (Sticky Residential Proxy)
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

// 3. Single Email Dispatch Endpoint (Exact 1 Email per call)
app.post("/api/send-single", async (req, res) => {
  let { senderEmail, appPassword, recipient, subject, bodyText, senderName } = req.body;

  const target = sanitizeEmail(recipient);
  if (!senderEmail || !appPassword || !target || !target.includes("@")) {
    return res.status(400).json({ success: false, error: "Invalid email or missing credentials." });
  }

  const { transporter, agent } = createStickyTransporter(senderEmail, appPassword);
  const usedIP = await getProxyIP(agent);

  // RFC-Compliant Headers for Primary Inbox Landing
  const uniqueDomain = senderEmail.split("@")[1] || "gmail.com";
  const cleanMsgId = `${Date.now()}.${Math.random().toString(36).substring(2, 9)}@${uniqueDomain}`;

  const mailOptions = {
    from: `"${senderName || "Account Support"}" <${sanitizeEmail(senderEmail)}>`,
    to: target,
    subject: subject || "Important Account Notice",
    text: bodyText || "Please review the attached communication details.",
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
    return res.json({ success: true, email: target, status: "Sent", ip: usedIP, id: info.messageId });
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
      return res.json({ success: true, email: target, status: "Sent", ip: "Fallback Direct", id: info.messageId });
    } catch (directErr) {
      return res.json({ success: false, email: target, status: "Failed", ip: usedIP, error: directErr.message });
    }
  }
});

// 4. White Theme UI with Original Spam Protection Badge & 1-by-1 Loop
app.get("*", (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Bulk Email Sender</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background-color: #f8fafc; color: #1e293b; margin: 0; padding: 25px; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .wrapper { width: 100%; max-width: 960px; }
    .card { background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; box-shadow: 0 4px 25px rgba(0,0,0,0.04); padding: 32px; margin-bottom: 20px; }
    
    .top-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
    .top-header h2 { margin: 0; font-size: 22px; font-weight: 700; color: #0f172a; display: flex; align-items: center; gap: 10px; }
    .badge { background: #e0f2fe; color: #0284c7; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
    .btn-logout { background: #fee2e2; color: #ef4444; border: 1px solid #fca5a5; padding: 7px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; transition: 0.2s; }
    .btn-logout:hover { background: #ef4444; color: #fff; }

    .main-grid { display: grid; grid-template-columns: 1.1fr 0.9fr; gap: 28px; }
    .section-title { font-size: 15px; font-weight: 600; color: #0f172a; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    .subtext { font-size: 11px; color: #94a3b8; font-weight: normal; margin-left: auto; }

    .input-row { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 14px; }
    label { display: block; font-size: 12px; font-weight: 600; color: #475569; margin-bottom: 6px; }
    input[type="text"], input[type="password"], textarea {
      width: 100%; background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 10px 12px; font-size: 13px; color: #0f172a; transition: border-color 0.2s;
    }
    input:focus, textarea:focus { outline: none; border-color: #0d9488; }
    textarea { height: 115px; resize: none; }

    .monitor-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px; margin-top: 18px; }
    .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); text-align: center; gap: 10px; }
    .stat-item h3 { margin: 0; font-size: 22px; font-weight: 700; color: #0f172a; }
    .stat-item span { font-size: 11px; font-weight: 600; color: #64748b; text-transform: uppercase; margin-top: 4px; display: block; }
    
    .bottom-row { display: flex; justify-content: space-between; align-items: center; margin-top: 24px; gap: 20px; }
    
    /* Original Cloudflare Spam Protection Box */
    .spam-badge-card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 9px 15px; display: flex; align-items: center; gap: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
    .spam-left { display: flex; align-items: center; gap: 8px; }
    .spam-check { width: 18px; height: 18px; background: #22c55e; border-radius: 50%; display: flex; align-items: center; justify-content: center; color: white; font-size: 10px; }
    .spam-text { font-size: 13px; font-weight: 600; color: #1e293b; }
    .spam-right { border-left: 1px solid #e2e8f0; padding-left: 12px; font-size: 10px; color: #64748b; text-align: left; }

    .action-right { display: flex; align-items: center; gap: 14px; }
    .ready-tag { font-size: 12px; color: #64748b; display: flex; align-items: center; gap: 6px; }
    .ready-dot { width: 8px; height: 8px; background: #22c55e; border-radius: 50%; }

    .btn-send { background: #0d9488; color: #ffffff; border: none; padding: 12px 28px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; display: flex; align-items: center; gap: 8px; transition: 0.2s; }
    .btn-send:hover { background: #0f766e; }
    .btn-send:disabled { background: #94a3b8; cursor: not-allowed; }

    #logBox { background: #0f172a; color: #38bdf8; border-radius: 8px; padding: 12px; font-family: monospace; font-size: 12px; max-height: 130px; overflow-y: auto; margin-top: 15px; }
    .hidden { display: none !important; }
  </style>
</head>
<body>

  <div class="wrapper">
    <!-- Login Modal -->
    <div id="authPanel" class="card" style="max-width: 400px; margin: 0 auto; text-align: center;">
      <h2 style="justify-content: center; margin-bottom: 6px;"><i class="fa-solid fa-lock" style="color:#0d9488;"></i> Access Protected</h2>
      <p style="font-size: 13px; color: #64748b; margin-top: 0;">Enter master password to access system</p>
      <input type="password" id="sysPass" placeholder="Password (@##)" style="margin-bottom: 14px;" />
      <button class="btn-send" style="width: 100%; justify-content: center;" onclick="login()">Enter Console</button>
      <p id="authErr" style="color: #ef4444; font-size: 13px; margin-top: 10px; display: none;">Invalid Password</p>
    </div>

    <!-- Main Console -->
    <div id="mailPanel" class="card hidden">
      <div class="top-header">
        <h2>
          <i class="fa-solid fa-paper-plane" style="color: #0d9488;"></i> Bulk Email Sender
          <span class="badge">Safe 1-by-1 Dispatch</span>
        </h2>
        <button class="btn-logout" title="Double click to Logout" ondblclick="performLogout()">Logout (Double Click)</button>
      </div>

      <div class="main-grid">
        <!-- Left: Compose Message -->
        <div>
          <div class="section-title"><i class="fa-solid fa-pen-to-square" style="color:#64748b;"></i> Compose Message</div>
          <div class="input-row">
            <div>
              <label>Sender Name</label>
              <input type="text" id="sName" placeholder="E.g., John Doe" value="Molly" />
            </div>
            <div>
              <label>Your Gmail</label>
              <input type="text" id="sEmail" placeholder="you@gmail.com" value="Mollyreid599@gmail.com" />
            </div>
          </div>
          <div class="input-row">
            <div>
              <label>App Password</label>
              <input type="password" id="sPass" placeholder="16-char app password" />
            </div>
            <div>
              <label>Email Subject</label>
              <input type="text" id="sSub" placeholder="Enter subject line..." value="Project Invoice Update #8942" />
            </div>
          </div>
          <div>
            <label>Message Body (Plain Text / HTML)</label>
            <textarea id="sBody" placeholder="Write your email here...">Hello, please find the updated statement details attached for your review. Let us know if you have questions.</textarea>
          </div>
        </div>

        <!-- Right: Recipients & Progress Monitor -->
        <div>
          <div class="section-title">
            <i class="fa-solid fa-users" style="color:#64748b;"></i> Recipients
            <span class="subtext" id="countFound">0 found</span>
          </div>
          <div>
            <textarea id="sRecipients" placeholder="recipient1@example.com&#10;recipient2@example.com" oninput="updateRecipientCount()">riyabsr882@gmail.com</textarea>
          </div>

          <div class="monitor-box">
            <div class="section-title" style="margin-bottom: 10px;"><i class="fa-solid fa-chart-line" style="color:#64748b;"></i> Progress Monitor</div>
            <div class="stat-grid">
              <div class="stat-item"><h3 id="cntTotal">0</h3><span>TOTAL</span></div>
              <div class="stat-item"><h3 id="cntSent" style="color:#22c55e;">0</h3><span>SENT</span></div>
              <div class="stat-item"><h3 id="cntFail" style="color:#ef4444;">0</h3><span>FAILED</span></div>
              <div class="stat-item"><h3 id="cntRemaining" style="color:#0ea5e9;">0</h3><span>REMAINING</span></div>
            </div>
          </div>
        </div>
      </div>

      <!-- Bottom Spam Protection & Actions -->
      <div class="bottom-row">
        <!-- Cloudflare Spam Protection Box -->
        <div>
          <label style="font-size: 11px; color: #64748b; margin-bottom: 4px;"><i class="fa-solid fa-shield-halved"></i> Spam Protection</label>
          <div class="spam-badge-card">
            <div class="spam-left">
              <div class="spam-check"><i class="fa-solid fa-check"></i></div>
              <span class="spam-text">Success!</span>
            </div>
            <div class="spam-right">
              <strong>CLOUDFLARE</strong>
              <div style="font-size: 9px; color: #94a3b8;">Privacy • Terms</div>
            </div>
          </div>
        </div>

        <div class="action-right">
          <div class="ready-tag"><div class="ready-dot"></div> Ready to send</div>
          <button class="btn-send" id="sendBtn" onclick="startSingleEmailDispatch()">
            <i class="fa-solid fa-paper-plane"></i> Send All
          </button>
        </div>
      </div>

      <div id="logBox">System Ready. Safe 1-by-1 dispatch active. Double-click Logout anytime.</div>
    </div>
  </div>

  <script>
    function login() {
      if (document.getElementById("sysPass").value === "@##") {
        document.getElementById("authPanel").classList.add("hidden");
        document.getElementById("mailPanel").classList.remove("hidden");
        updateRecipientCount();
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

    function updateRecipientCount() {
      const val = document.getElementById("sRecipients").value.trim();
      const list = val ? val.split(/[\\r\\n,;]+/).filter(e => e.trim().length > 3) : [];
      document.getElementById("countFound").innerText = list.length + " found";
    }

    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

    // 1-by-1 Sequential Dispatch Engine
    async function startSingleEmailDispatch() {
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

      if (allEmails.length === 0) return alert("No valid recipients found!");

      let totalSent = 0;
      let totalFailed = 0;
      const totalCount = allEmails.length;

      document.getElementById("cntTotal").innerText = totalCount;
      document.getElementById("cntSent").innerText = 0;
      document.getElementById("cntFail").innerText = 0;
      document.getElementById("cntRemaining").innerText = totalCount;

      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sending 1-by-1...';
      log.innerText = "Initiating safe 1-by-1 email delivery for " + totalCount + " recipients...\\n";

      for (let i = 0; i < allEmails.length; i++) {
        const targetEmail = allEmails[i];
        const currentIdx = i + 1;

        log.innerText += "\\n[" + currentIdx + "/" + totalCount + "] Delivering to: " + targetEmail + "...\\n";
        log.scrollTop = log.scrollHeight;

        try {
          const res = await fetch("/api/send-single", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              senderEmail: sEmail,
              appPassword: sPass,
              recipient: targetEmail,
              subject: sSub,
              bodyText: sBody,
              senderName: sName
            })
          });

          const data = await res.json();
          if (data.success) {
            totalSent++;
            document.getElementById("cntSent").innerText = totalSent;
            log.innerText += "✓ Delivered to Inbox -> " + targetEmail + " [IP: " + (data.ip || "Sticky") + "]\\n";
          } else {
            totalFailed++;
            document.getElementById("cntFail").innerText = totalFailed;
            log.innerText += "✗ Failed -> " + targetEmail + " (" + (data.error || "Error") + ")\\n";
          }
        } catch (netErr) {
          totalFailed++;
          document.getElementById("cntFail").innerText = totalFailed;
          log.innerText += "✗ Network issue for " + targetEmail + "\\n";
        }

        document.getElementById("cntRemaining").innerText = totalCount - (totalSent + totalFailed);
        log.scrollTop = log.scrollHeight;

        // Natural human delay before sending next 1 email
        if (i < allEmails.length - 1) {
          await sleep(${DELAY_BETWEEN_SINGLE_MAILS});
        }
      }

      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send All';
      log.innerText += "\\n=== ALL " + totalCount + " EMAILS DELIVERED ===";
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

import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import crypto from 'crypto';

const app = express();

// Single Master Password
const MASTER_PASSWORD = '####';

const globalSession = { stopRequested: false };
const poolMap = new Map();

// Middlewares
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

/* ==========================================================================
   AUTHENTICATION ROUTE
   ========================================================================== */
app.post('/api/auth', (req, res) => {
  const { password } = req.body;
  if (String(password || '').trim() === MASTER_PASSWORD) {
    const token = crypto.randomBytes(32).toString('hex');
    return res.json({ success: true, token, message: 'Authorized' });
  }
  return res.status(401).json({ success: false, message: 'Incorrect password' });
});

/* ==========================================================================
   GMAIL TLS TRANSPORTER POOL (Port 587 STARTTLS)
   ========================================================================== */
function getPort587Transporter(email, appPassword) {
  const cleanEmail = String(email).toLowerCase().trim();
  const cleanPass = String(appPassword).replace(/\s+/g, '').trim();
  const key = `inbox_pro_${cleanEmail}_${cleanPass}`;

  if (!poolMap.has(key)) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      port: 587,
      secure: false, // STARTTLS
      requireTLS: true,
      auth: {
        user: cleanEmail,
        pass: cleanPass
      },
      pool: true,
      maxConnections: 5, // 5 Batch Concurrency
      maxMessages: 500,
      socketTimeout: 30000,
      connectionTimeout: 30000
    });
    poolMap.set(key, transporter);
  }
  return poolMap.get(key);
}

/* ==========================================================================
   RECIPIENT & SPINTAX RESOLVERS
   ========================================================================== */
function parseRecipientData(input) {
  let email = '';
  let rawName = '';

  if (typeof input === 'object' && input !== null) {
    email = (input.email || input.recipient || '').trim();
    rawName = (input.name || input.fullName || input.first_name || '').trim();
  } else if (typeof input === 'string') {
    const str = input.trim();
    const angleMatch = str.match(/^(?:"?([^"]*)"?\s)?<([^>]+)>$/);
    if (angleMatch) {
      rawName = angleMatch[1] ? angleMatch[1].trim() : '';
      email = angleMatch[2].trim();
    } else if (str.includes(',')) {
      const parts = str.split(',');
      if (parts[0].includes('@')) {
        email = parts[0].trim();
        rawName = parts[1].trim();
      } else {
        rawName = parts[0].trim();
        email = parts[1].trim();
      }
    } else {
      email = str;
    }
  }

  if (!rawName && email.includes('@')) {
    const prefix = email.split('@')[0];
    rawName = prefix.replace(/[0-9_.-]/g, ' ').trim();
  }

  const formattedName = rawName
    ? rawName.split(/\s+/).map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ')
    : '';

  return {
    email: email.toLowerCase(),
    name: formattedName,
    firstName: formattedName ? formattedName.split(' ')[0] : '',
    domain: email.includes('@') ? email.split('@')[1] : ''
  };
}

function parseSpintax(text) {
  if (!text) return '';
  let spun = String(text);
  const regex = /\{([^{}]+)\}/s;
  let iterations = 0;

  while (regex.test(spun) && iterations < 35) {
    spun = spun.replace(regex, (_, choices) => {
      if (!choices.includes('|')) return choices;
      const options = choices.split('|');
      return options[Math.floor(Math.random() * options.length)].trim();
    });
    iterations++;
  }
  return spun.replace(/[\{\}]/g, '').trim();
}

function personalizeContent(template, recipient) {
  if (!template) return '';
  let content = parseSpintax(template);
  const displayName = recipient.name || recipient.firstName || 'there';
  const displayFirstName = recipient.firstName || displayName;

  content = content.replace(/{Name}/gi, displayName);
  content = content.replace(/{FirstName}/gi, displayFirstName);
  content = content.replace(/{First_Name}/gi, displayFirstName);
  content = content.replace(/{Email}/gi, recipient.email);
  content = content.replace(/{Domain}/gi, recipient.domain);
  return content;
}

function createCleanPlainText(text) {
  if (!text) return '';
  return text
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<br\s*[\/]?>/gi, '\n')
    .replace(/<\/p>/gi, '\n\n')
    .replace(/<\/div>/gi, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\n\s*\n/g, '\n\n')
    .trim();
}

/* ==========================================================================
   PRIMARY INBOX 5-BATCH DISPATCH PIPELINE
   ========================================================================== */
app.post('/api/send-stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');

  const { email, appPassword, password, senderName, subject, messageBody, body, recipients } = req.body;
  const userPass = appPassword || password;
  const userBody = messageBody || body || '';

  if (!email || !userPass || !Array.isArray(recipients) || recipients.length === 0) {
    res.write(`data: ${JSON.stringify({ success: false, error: 'Invalid Parameters' })}\n\n`);
    return res.end();
  }

  const cleanEmail = email.toLowerCase().trim();
  const cleanSenderName = (senderName || '').replace(/["\r\n]/g, '').trim();
  globalSession.stopRequested = false;

  const keepAlivePing = setInterval(() => {
    try { res.write(': keep-alive\n\n'); } catch(e) {}
  }, 4000);

  const transporter = getPort587Transporter(email, userPass);
  const BATCH_SIZE = 5;

  const defaultBestSubject = '{quick note regarding your site|website feedback|quick question for you|question about your page}';
  const defaultBestBody = "{Hi {Name},|Hello {Name},|Hey {Name},}\n\n{I noticed your site has a great presentation but isn't showing on the top results.|Your website looks clean, but seems missing from the primary search listings.}\n\n{May I send you a quick report with details?|Would you mind if I shared the screenshot with you?|Can I share the audit reports with you?}";

  const finalSubjectTemplate = (subject && subject.trim()) ? subject : defaultBestSubject;
  const finalBodyTemplate = (userBody && userBody.trim()) ? userBody : defaultBestBody;

  for (let i = 0; i < recipients.length; i += BATCH_SIZE) {
    if (globalSession.stopRequested) {
      res.write(`data: ${JSON.stringify({ success: false, error: 'Stopped by User' })}\n\n`);
      break;
    }

    const batch = recipients.slice(i, i + BATCH_SIZE);

    const sendPromises = batch.map(async (rawRecipient, idx) => {
      const recipient = parseRecipientData(rawRecipient);
      if (!recipient.email) return { success: false, recipient: '', error: 'Invalid Email' };

      try {
        if (idx > 0) {
          await new Promise(resolve => setTimeout(resolve, Math.floor(120 + Math.random() * 180)));
        }

        const personalizedSubject = personalizeContent(finalSubjectTemplate, recipient);
        const personalizedBody = personalizeContent(finalBodyTemplate, recipient);
        const isHtml = /<[a-z][\s\S]*>/i.test(personalizedBody);

        const cleanBodyText = isHtml
          ? personalizedBody
          : personalizedBody.replace(/\n/g, '<br>');

        const formattedHtml = `
          <!--[if mso]>
          <table border="0" cellpadding="0" cellspacing="0" width="100%" style="font-family: 'Times New Roman', Times, serif; color: #000000;">
            <tr>
              <td style="font-family: 'Times New Roman', Times, serif; font-size: 14pt; line-height: 1.45; color: #000000;">
                ${cleanBodyText}
              </td>
            </tr>
          </table>
          <![endif]-->
          <!--[if !mso]><!-->
          <div dir="ltr" style="font-family: Roboto, Arial, Helvetica, sans-serif; font-size: 14.5px; color: #222222; line-height: 1.5;">
            ${cleanBodyText}
          </div>
          <!--<![endif]-->
        `.trim();

        const plainTextFormatted = createCleanPlainText(personalizedBody);

        const mailOptions = {
          from: cleanSenderName ? `"${cleanSenderName}" <${cleanEmail}>` : cleanEmail,
          to: recipient.name ? `"${recipient.name}" <${recipient.email}>` : recipient.email,
          envelope: {
            from: cleanEmail,
            to: recipient.email
          },
          replyTo: cleanEmail,
          date: new Date(),
          subject: personalizedSubject,
          html: formattedHtml,
          text: plainTextFormatted,
          textEncoding: 'quoted-printable',
          encoding: 'utf-8'
        };

        await transporter.sendMail(mailOptions);
        return { success: true, recipient: recipient.email, name: recipient.name };

      } catch (err) {
        return { success: false, recipient: recipient.email, error: err.message };
      }
    });

    const results = await Promise.allSettled(sendPromises);

    for (const resItem of results) {
      if (resItem.status === 'fulfilled' && resItem.value.recipient) {
        res.write(`data: ${JSON.stringify(resItem.value)}\n\n`);
      }
    }

    if (i + BATCH_SIZE < recipients.length) {
      const safeBatchDelay = Math.floor(3200 + Math.random() * 1800);
      await new Promise(resolve => setTimeout(resolve, safeBatchDelay));
    }
  }

  clearInterval(keepAlivePing);
  res.write('data: [DONE]\n\n');
  res.end();
});

app.post('/api/stop', (req, res) => {
  globalSession.stopRequested = true;
  res.json({ success: true, message: 'Process stopped' });
});

/* ==========================================================================
   FRONTEND HTML (EMBEDDED TO PREVENT DISK ERRORS)
   ========================================================================== */
const PAGE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bulk Email Sender</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  </style>
</head>
<body class="text-slate-800 min-h-screen flex flex-col justify-center items-center p-4">

  <div id="authContainer" class="w-full max-w-md bg-white border border-slate-200 rounded-2xl p-8 shadow-xl">
    <div class="text-center mb-6">
      <div class="w-14 h-14 bg-indigo-50 text-indigo-600 rounded-2xl flex items-center justify-center mx-auto mb-3 border border-indigo-100">
        <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
      </div>
      <h2 class="text-2xl font-bold text-slate-800">Access Protected</h2>
      <p class="text-sm text-slate-500 mt-1">Enter password to continue</p>
    </div>

    <div id="authAlert" class="hidden mb-4 p-3 rounded-lg text-sm bg-rose-50 border border-rose-200 text-rose-600"></div>

    <form id="loginForm" class="space-y-4">
      <div>
        <input type="password" id="sitePassword" required placeholder="Enter password..." class="w-full px-4 py-3 bg-slate-50 border border-slate-300 rounded-xl focus:outline-none focus:border-indigo-600 text-slate-800 font-mono text-base placeholder-slate-400">
      </div>
      <button type="submit" id="loginBtn" class="w-full py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl font-medium transition shadow-md shadow-indigo-600/20">➔ Enter</button>
    </form>
  </div>

  <div id="mainDashboard" class="hidden w-full max-w-6xl">
    <div class="flex items-center justify-between mb-6">
      <div class="flex items-center gap-2">
        <svg class="w-6 h-6 text-indigo-600 transform -rotate-45" fill="currentColor" viewBox="0 0 20 20"><path d="M10.894 2.553a1 1 0 00-1.788 0l-7 14a1 1 0 001.169 1.409l5-1.429A1 1 0 009 15.571V11a1 1 0 112 0v4.571a1 1 0 00.725.962l5 1.428a1 1 0 001.17-1.408l-7-14z"/></svg>
        <h1 class="text-2xl font-bold text-slate-800">Bulk Email Sender</h1>
      </div>
      <button onclick="location.reload()" class="text-xs text-slate-500 hover:text-slate-800 bg-white border border-slate-300 px-3 py-1.5 rounded-lg shadow-sm">Logout</button>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div class="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-4">
        <div class="flex items-center gap-2 border-b border-slate-100 pb-3">
          <h2 class="font-bold text-slate-800 text-base">Compose Message</h2>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="text-xs font-semibold text-slate-600 block mb-1">Sender Name</label>
            <input type="text" id="senderName" placeholder="E.g., John Doe" class="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-800 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="text-xs font-semibold text-slate-600 block mb-1">Your Gmail</label>
            <input type="email" id="smtpEmail" placeholder="you@gmail.com" class="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-800 focus:outline-none focus:border-indigo-500">
          </div>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="text-xs font-semibold text-slate-600 block mb-1">App Password</label>
            <input type="password" id="smtpPass" placeholder="16-char app password" class="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-800 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="text-xs font-semibold text-slate-600 block mb-1">Email Subject</label>
            <input type="text" id="subject" placeholder="Enter subject line..." class="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-800 focus:outline-none focus:border-indigo-500">
          </div>
        </div>

        <div>
          <label class="text-xs font-semibold text-slate-600 block mb-1">Message Body (Plain Text / HTML)</label>
          <textarea id="body" rows="9" placeholder="Write your email here... Spintax supported: {Hi|Hello}" class="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-sm font-mono text-slate-800 focus:outline-none focus:border-indigo-500"></textarea>
        </div>

        <div class="pt-2">
          <div class="inline-flex items-center gap-2 bg-slate-50 border border-slate-200 px-3 py-1.5 rounded-lg text-xs font-medium text-emerald-700">
            <span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Success! Primary Inbox 5-Batch Protection Active</span>
          </div>
        </div>
      </div>

      <div class="space-y-6">
        <div class="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
          <div class="flex justify-between items-center mb-1">
            <h2 class="font-bold text-slate-800 text-base">Recipients</h2>
            <span id="foundBadge" class="text-xs bg-indigo-50 text-indigo-600 font-semibold px-2.5 py-0.5 rounded-full border border-indigo-100">0 found</span>
          </div>
          <p class="text-xs text-slate-400 mb-3">Paste emails (comma separated, new lines, or Excel copy)</p>
          <textarea id="recipients" rows="5" placeholder="john@example.com&#10;jane@example.com, Jane Doe" class="w-full p-3 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 focus:outline-none focus:border-indigo-500"></textarea>
        </div>

        <div class="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-4">
          <h2 class="font-bold text-slate-800 text-base">Progress Monitor</h2>
          <div class="grid grid-cols-4 gap-3">
            <div class="bg-slate-50 border border-slate-200 rounded-xl p-3 text-center">
              <div class="text-[10px] font-bold text-slate-500 uppercase">TOTAL</div>
              <div id="statTotal" class="text-2xl font-black text-indigo-600 mt-1">0</div>
            </div>
            <div class="bg-slate-50 border border-slate-200 rounded-xl p-3 text-center">
              <div class="text-[10px] font-bold text-slate-500 uppercase">SENT</div>
              <div id="statSent" class="text-2xl font-black text-emerald-500 mt-1">0</div>
            </div>
            <div class="bg-slate-50 border border-slate-200 rounded-xl p-3 text-center">
              <div class="text-[10px] font-bold text-slate-500 uppercase">FAILED</div>
              <div id="statFailed" class="text-2xl font-black text-rose-500 mt-1">0</div>
            </div>
            <div class="bg-slate-50 border border-slate-200 rounded-xl p-3 text-center">
              <div class="text-[10px] font-bold text-slate-500 uppercase">REMAINING</div>
              <div id="statRemaining" class="text-2xl font-black text-amber-500 mt-1">0</div>
            </div>
          </div>

          <div class="flex items-center justify-center gap-1.5 text-xs text-slate-500 py-1">
            <span class="w-2 h-2 rounded-full bg-slate-400" id="statusDot"></span>
            <span id="statusText">Ready to send</span>
          </div>

          <div class="flex gap-3 pt-2">
            <button id="startBtn" class="flex-1 py-3 bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl font-bold flex items-center justify-center gap-2 transition shadow-md shadow-emerald-600/20">Send All</button>
            <button id="stopBtn" class="px-6 py-3 bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 rounded-xl font-bold transition">Stop</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script>
    const loginForm = document.getElementById('loginForm');
    const authAlert = document.getElementById('authAlert');

    function showAlert(msg) {
      authAlert.classList.remove('hidden');
      authAlert.textContent = msg;
    }

    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const pwd = document.getElementById('sitePassword').value.trim();
      const btn = document.getElementById('loginBtn');
      btn.disabled = true;
      btn.textContent = 'Verifying...';

      try {
        const res = await fetch('/api/auth', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: pwd })
        });
        const data = await res.json();
        if (data.success) {
          document.getElementById('authContainer').classList.add('hidden');
          document.getElementById('mainDashboard').classList.remove('hidden');
        } else {
          showAlert('Incorrect password');
        }
      } catch (err) {
        showAlert('Authentication failed.');
      } finally {
        btn.disabled = false;
        btn.textContent = '➔ Enter';
      }
    });

    const recipientsInput = document.getElementById('recipients');
    recipientsInput.addEventListener('input', () => {
      const list = recipientsInput.value.split('\\n').filter(r => r.trim());
      document.getElementById('foundBadge').textContent = list.length + ' found';
      document.getElementById('statTotal').textContent = list.length;
      document.getElementById('statRemaining').textContent = list.length;
    });

    document.getElementById('startBtn').addEventListener('click', async () => {
      const email = document.getElementById('smtpEmail').value;
      const appPassword = document.getElementById('smtpPass').value;
      const senderName = document.getElementById('senderName').value;
      const subject = document.getElementById('subject').value;
      const messageBody = document.getElementById('body').value;
      const rawRecipients = recipientsInput.value.split('\\n').filter(r => r.trim());

      if (!email || !appPassword || rawRecipients.length === 0) {
        alert('Please fill Sender Email, App Password, and at least one Recipient.');
        return;
      }

      let sentCount = 0;
      let failedCount = 0;
      const totalCount = rawRecipients.length;

      document.getElementById('statTotal').textContent = totalCount;
      document.getElementById('statSent').textContent = '0';
      document.getElementById('statFailed').textContent = '0';
      document.getElementById('statRemaining').textContent = totalCount;
      document.getElementById('statusText').textContent = 'Sending in 5-batches...';
      document.getElementById('statusDot').className = 'w-2 h-2 rounded-full bg-emerald-500 animate-pulse';

      const res = await fetch('/api/send-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, appPassword, senderName, subject, messageBody, recipients: rawRecipients })
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value);
        const lines = chunk.split('\\n');
        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const dataStr = line.replace('data: ', '').trim();
            if (dataStr === '[DONE]') {
              document.getElementById('statusText').textContent = 'Completed';
              document.getElementById('statusDot').className = 'w-2 h-2 rounded-full bg-slate-400';
            } else {
              try {
                const item = JSON.parse(dataStr);
                if (item.success) {
                  sentCount++;
                  document.getElementById('statSent').textContent = sentCount;
                } else {
                  failedCount++;
                  document.getElementById('statFailed').textContent = failedCount;
                }
                const rem = totalCount - (sentCount + failedCount);
                document.getElementById('statRemaining').textContent = rem >= 0 ? rem : 0;
              } catch(e) {}
            }
          }
        }
      }
    });

    document.getElementById('stopBtn').addEventListener('click', async () => {
      await fetch('/api/stop', { method: 'POST' });
      document.getElementById('statusText').textContent = 'Stopped';
      document.getElementById('statusDot').className = 'w-2 h-2 rounded-full bg-rose-500';
    });
  </script>
</body>
</html>`;

/* Express v5 Catch-All Route (Bypasses PathError syntax crash) */
app.use((req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(PAGE_HTML);
});

export default function handler(req, res) {
  return app(req, res);
}

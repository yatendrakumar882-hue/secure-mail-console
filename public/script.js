document.addEventListener('DOMContentLoaded', () => {
  const authOverlay = document.getElementById('authOverlay');
  const sitePassword = document.getElementById('sitePassword');
  const authBtn = document.getElementById('authBtn');
  const authError = document.getElementById('authError');
  const logoutBtn = document.getElementById('logoutBtn');

  const senderName = document.getElementById('senderName');
  const senderEmail = document.getElementById('senderEmail');
  const appPassword = document.getElementById('appPassword');
  const emailSubject = document.getElementById('emailSubject');
  const messageBody = document.getElementById('messageBody');
  const recipientList = document.getElementById('recipientList');
  const recipientCount = document.getElementById('recipientCount');

  const statTotal = document.getElementById('statTotal');
  const statSent = document.getElementById('statSent');
  const statFailed = document.getElementById('statFailed');
  const statRemaining = document.getElementById('statRemaining');
  const statusText = document.getElementById('statusText');
  const statusDot = document.getElementById('statusDot');

  const sendBtn = document.getElementById('sendBtn');
  const stopBtn = document.getElementById('stopBtn');
  const togglePassword = document.getElementById('togglePassword');

  let totalCount = 0;
  let sentCount = 0;
  let failedCount = 0;

  // Session check
  if (sessionStorage.getItem('auth_token') === 'authorized') {
    authOverlay.style.display = 'none';
  }

  authBtn.addEventListener('click', async () => {
    const password = sitePassword.value.trim();
    if (!password) return;

    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      });
      const data = await res.json();
      if (data.success) {
        sessionStorage.setItem('auth_token', 'authorized');
        authOverlay.style.display = 'none';
      } else {
        authError.textContent = 'Invalid password';
      }
    } catch {
      authError.textContent = 'Auth server error';
    }
  });

  logoutBtn.addEventListener('dblclick', () => {
    sessionStorage.removeItem('auth_token');
    window.location.reload();
  });

  togglePassword.addEventListener('click', () => {
    appPassword.type = appPassword.type === 'password' ? 'text' : 'password';
  });

  // Recipient parsing
  function extractRecipients() {
    const raw = recipientList.value;
    const lines = raw.split(/[\n,]+/).map(e => e.trim()).filter(Boolean);
    const valid = lines.filter(item => item.includes('@'));
    recipientCount.textContent = `${valid.length} found`;
    return valid;
  }

  recipientList.addEventListener('input', extractRecipients);

  sendBtn.addEventListener('click', async () => {
    const recipients = extractRecipients();
    if (!recipients.length) {
      alert('Please add at least 1 valid recipient email.');
      return;
    }
    if (!senderEmail.value.trim() || !appPassword.value.trim()) {
      alert('Please provide your Gmail and 16-character App Password.');
      return;
    }

    let cfToken = '';
    try {
      if (window.turnstile) {
        cfToken = window.turnstile.getResponse();
      }
    } catch {}

    totalCount = recipients.length;
    sentCount = 0;
    failedCount = 0;

    statTotal.textContent = totalCount;
    statSent.textContent = '0';
    statFailed.textContent = '0';
    statRemaining.textContent = totalCount;

    sendBtn.style.display = 'none';
    stopBtn.style.display = 'block';
    statusText.textContent = 'Dispatching 2 emails/blitch...';
    statusDot.style.backgroundColor = '#f59e0b';

    try {
      const res = await fetch('/api/send-stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          senderName: senderName.value.trim(),
          email: senderEmail.value.trim(),
          appPassword: appPassword.value.trim(),
          subject: emailSubject.value.trim(),
          messageBody: messageBody.value,
          recipients,
          cfToken
        })
      });

      const reader = res.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const rawData = line.replace('data: ', '').trim();
            if (rawData === '[DONE]') {
              statusText.textContent = 'Completed';
              statusDot.style.backgroundColor = '#22c55e';
              break;
            }

            try {
              const item = JSON.parse(rawData);
              if (item.success) {
                sentCount++;
                statSent.textContent = sentCount;
              } else {
                failedCount++;
                statFailed.textContent = failedCount;
              }
              const remaining = Math.max(0, totalCount - (sentCount + failedCount));
              statRemaining.textContent = remaining;
            } catch {}
          }
        }
      }
    } catch (err) {
      statusText.textContent = 'Stream stopped';
      statusDot.style.backgroundColor = '#ef4444';
    } finally {
      sendBtn.style.display = 'flex';
      stopBtn.style.display = 'none';
      if (window.turnstile) window.turnstile.reset();
    }
  });

  stopBtn.addEventListener('click', async () => {
    await fetch('/api/stop', { method: 'POST' });
    statusText.textContent = 'Stopped by user';
    statusDot.style.backgroundColor = '#ef4444';
    sendBtn.style.display = 'flex';
    stopBtn.style.display = 'none';
  });
});

document.addEventListener('DOMContentLoaded', () => {
  const dashboardEmail = document.getElementById('dashboard-email');
  const dashboardPassword = document.getElementById('dashboard-password');
  const senderName = document.getElementById('sender-name');
  const subject = document.getElementById('subject');
  const messageBody = document.getElementById('message-body');
  const recipientsInput = document.getElementById('recipients-input');
  const sendBtn = document.getElementById('send-btn');
  const stopBtn = document.getElementById('stop-btn');
  const statusText = document.getElementById('status-text');

  let extractedEmails = [];
  let isSending = false;
  let stopRequested = false;

  recipientsInput.addEventListener('input', () => {
    const matches = recipientsInput.value.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi) || [];
    extractedEmails = [...new Set(matches.map(e => e.toLowerCase()))];
  });

  sendBtn.addEventListener('click', async () => {
    if (isSending) return;
    if (!dashboardEmail.value.trim() || !dashboardPassword.value.trim() || !senderName.value.trim() || !subject.value.trim() || !messageBody.value.trim()) {
      alert("Fill all fields");
      return;
    }
    if (extractedEmails.length === 0) {
      alert("No recipients");
      return;
    }

    const emailVal = dashboardEmail.value.trim();
    const appPasswordVal = dashboardPassword.value.trim();
    const turnstileResponse = document.querySelector('[name="cf-turnstile-response"]')?.value;

    sendBtn.disabled = true;
    statusText.textContent = "Sending...";

    try {
      const payload = { email: emailVal, appPassword: appPasswordVal, senderName: senderName.value.trim(), subject: subject.value.trim(), messageBody: messageBody.value.trim(), recipients: extractedEmails, cfToken: turnstileResponse };
      const response = await fetch('/api/send-batch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const result = await response.json();

      if (!result.success && result.message && result.message.includes("Mail Limit Full")) {
        alert("❌ Mail Limit Full ❌\nThis Gmail ID has reached its hourly limit (28 mails).");
      } else {
        alert("Sent: " + result.results.sent + " Failed: " + result.results.failed);
      }
    } catch {
      alert("Error sending");
    } finally {
      sendBtn.disabled = false;
      statusText.textContent = "Ready to send";
    }
  });
});

// Track Gmail usage
const gmailUsage = {}; 
const MAX_PER_HOUR = 28;

function checkLimit(email) {
  const now = Date.now();
  if (!gmailUsage[email]) {
    gmailUsage[email] = { count: 0, resetTime: now + 3600000 };
  }
  if (now > gmailUsage[email].resetTime) {
    gmailUsage[email] = { count: 0, resetTime: now + 3600000 };
  }
  if (gmailUsage[email].count >= MAX_PER_HOUR) {
    return false;
  }
  gmailUsage[email].count++;
  return true;
}

app.post("/api/send-batch", async (req, res) => {
  const { email, appPassword, senderName, subject, messageBody, recipients, cfToken } = req.body;

  if (!email || !appPassword || !recipients?.length) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields"
    });
  }

  // Gmail ID limit check
  if (!checkLimit(email)) {
    return res.status(429).json({
      success: false,
      message: "Mail Limit Full ❌"
    });
  }

  if (recipients.length > 10) {
    return res.status(400).json({
        success: false,
        message: "Batch too large. Max 10."
    });
  }

  const transporter = createTransporter(email, appPassword);
  let sent = 0;
  let failed = 0;

  const results = await Promise.allSettled(recipients.map(recipient =>
      transporter.sendMail({
          from: `"${senderName}" <${email}>`,
          to: recipient,
          subject: subject,
          text: messageBody,
          html: `<p>${messageBody}</p>`
      }).then(() => ({ success: true, recipient }))
      .catch(error => {
          console.error("Email failed:", recipient, error);
          return { success: false, recipient, error: error.message };
      })
  ));

  for (const result of results) {
      if (result.status === 'fulfilled' && result.value.success) sent++;
      else failed++;
  }

  res.json({
      success: true,
      results: { sent, failed }
  });
});

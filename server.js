// Track Gmail usage
const gmailUsage = {}; // { email: { count: 0, resetTime: Date.now() } }
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
  const { email, recipients } = req.body;

  if (!checkLimit(email)) {
    return res.status(429).json({
      success: false,
      message: "Mail Limit Full ❌"
    });
  }

  // existing send logic...
});

app.post('/api/auth/verify-otp', (req, res) => {
  const { phone, otp, token } = req.body;
  const cleanPhone = (phone || '').replace(/\D/g, '').slice(-10);

  if (cleanPhone !== '6395991106') {
    return res.status(403).json({ success: false, message: 'Unauthorized Phone Number' });
  }

  // Master Access Passcode for DND numbers
  const inputOtp = String(otp).trim();
  if (inputOtp === '639599' || inputOtp === '991106') {
    return res.json({
      success: true,
      message: 'Access Granted via Master PIN',
      sessionToken: 'AUTH_SESSION_OK'
    });
  }

  const isValid = verifySignedToken(cleanPhone, inputOtp, token);
  if (!isValid) {
    return res.status(401).json({ success: false, message: 'Invalid OTP. Use authorized master PIN.' });
  }

  return res.json({
    success: true,
    message: 'Access Granted',
    sessionToken: 'AUTH_SESSION_OK'
  });
});

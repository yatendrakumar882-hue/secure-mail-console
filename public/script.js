document.addEventListener('DOMContentLoaded', () => {
    const passwordGate = document.getElementById('password-gate');
    const mainApp = document.getElementById('main-app');
    const gateForm = document.getElementById('gate-form');
    const gatePassword = document.getElementById('gate-password');
    const gateError = document.getElementById('gate-error');
    const gateSubmitBtn = document.getElementById('gate-submit-btn');

    // Authentication session check
    if (sessionStorage.getItem('authenticated') === 'true') {
        passwordGate?.classList.add('hidden');
        mainApp?.classList.remove('hidden');
    }

    if (gateForm) {
        gateForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = gatePassword.value.trim();
            if (!password) return;

            gateSubmitBtn.disabled = true;
            try {
                const res = await fetch('/api/auth', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                if (data.success) {
                    sessionStorage.setItem('authenticated', 'true');
                    passwordGate.classList.add('hidden');
                    mainApp.classList.remove('hidden');
                } else {
                    gateError.classList.remove('hidden');
                }
            } catch (err) {
                alert('Connection error. Please try again.');
            } finally {
                gateSubmitBtn.disabled = false;
            }
        });
    }

    const dashboardEmail = document.getElementById('dashboard-email');
    const dashboardPassword = document.getElementById('dashboard-password');
    const senderName = document.getElementById('sender-name');
    const subject = document.getElementById('subject');
    const messageBody = document.getElementById('message-body');
    const recipientsInput = document.getElementById('recipients-input');
    const sendBtn = document.getElementById('send-btn');
    const detectedCount = document.getElementById('detected-count');

    let extractedEmails = [];

    if (recipientsInput) {
        recipientsInput.addEventListener('input', () => {
            const matches = recipientsInput.value.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi) || [];
            extractedEmails = [...new Set(matches.map(e => e.toLowerCase().trim()))];
            if (detectedCount) {
                detectedCount.textContent = `${extractedEmails.length} found`;
            }
        });
    }

    if (sendBtn) {
        sendBtn.addEventListener('click', async () => {
            const emailVal = dashboardEmail.value.trim();
            const passVal = dashboardPassword.value.trim();
            const subjVal = subject.value.trim();
            const bodyVal = messageBody.value.trim();

            if (!emailVal || !passVal || !subjVal || !bodyVal) {
                return alert('Please fill in all required fields.');
            }
            if (extractedEmails.length === 0) {
                return alert('No valid recipient emails detected.');
            }

            sendBtn.disabled = true;
            sendBtn.textContent = 'Verifying Credentials...';

            try {
                const verifyRes = await fetch('/api/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: emailVal, appPassword: passVal })
                });

                const verifyData = await verifyRes.json();
                if (!verifyData.success) {
                    alert(verifyData.message || 'Authentication failed.');
                    sendBtn.disabled = false;
                    sendBtn.textContent = 'Send All';
                    return;
                }

                sendBtn.textContent = 'Processing Dispatches...';

                const response = await fetch('/api/send-stream', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: emailVal,
                        appPassword: passVal,
                        senderName: senderName.value.trim(),
                        subject: subjVal,
                        messageBody: bodyVal,
                        recipients: extractedEmails
                    })
                });

                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let buffer = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split('\n\n');
                    buffer = lines.pop();

                    for (const line of lines) {
                        if (line.startsWith('data: ')) {
                            const dataStr = line.replace('data: ', '').trim();
                            if (dataStr === '[DONE]') break;
                        }
                    }
                }

                alert('Operation completed successfully.');
            } catch (err) {
                console.error(err);
                alert('A network error occurred.');
            } finally {
                sendBtn.disabled = false;
                sendBtn.textContent = 'Send All';
            }
        });
    }
});

document.addEventListener('DOMContentLoaded', () => {

    // ==================== PASSWORD GATE ====================
    const passwordGate = document.getElementById('password-gate');
    const mainApp = document.getElementById('main-app');
    const gateForm = document.getElementById('gate-form');
    const gatePassword = document.getElementById('gate-password');
    const gateError = document.getElementById('gate-error');
    const gateSubmitBtn = document.getElementById('gate-submit-btn');
    const toggleGatePassword = document.getElementById('toggle-gate-password');

    if (sessionStorage.getItem('authenticated') === 'true') {
        passwordGate.classList.add('hidden');
        mainApp.classList.remove('hidden');
    } else {
        passwordGate.classList.remove('hidden');
        mainApp.classList.add('hidden');
    }

    toggleGatePassword.addEventListener('click', () => {
        const type = gatePassword.getAttribute('type') === 'password' ? 'text' : 'password';
        gatePassword.setAttribute('type', type);
        toggleGatePassword.innerHTML = type === 'password'
            ? '<i class="fa-regular fa-eye"></i>'
            : '<i class="fa-regular fa-eye-slash"></i>';
    });

    gateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = gatePassword.value.trim();
        if (!password) return;

        gateSubmitBtn.disabled = true;
        gateSubmitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...';
        gateError.classList.add('hidden');

        try {
            const response = await fetch('/api/auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            const result = await response.json();

            if (result.success) {
                sessionStorage.setItem('authenticated', 'true');
                passwordGate.classList.add('gate-unlocked');
                setTimeout(() => {
                    passwordGate.classList.add('hidden');
                    mainApp.classList.remove('hidden');
                }, 550);
            } else {
                gateError.classList.remove('hidden');
                gatePassword.value = '';
                gatePassword.focus();
            }
        } catch {
            gateError.querySelector('span').textContent = 'Connection error. Try again.';
            gateError.classList.remove('hidden');
        } finally {
            gateSubmitBtn.disabled = false;
            gateSubmitBtn.innerHTML = '<i class="fa-solid fa-arrow-right-to-bracket"></i> Enter';
        }
    });

    // ==================== MAIN APP LOGIC ====================
    const dashboardEmail = document.getElementById('dashboard-email');
    const dashboardPassword = document.getElementById('dashboard-password');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const senderName = document.getElementById('sender-name');
    const subject = document.getElementById('subject');
    const messageBody = document.getElementById('message-body');
    const recipientsInput = document.getElementById('recipients-input');
    const detectedCount = document.getElementById('detected-count');
    const emailValidationError = document.getElementById('email-validation-error');

    const statTotal = document.getElementById('stat-total');
    const statSent = document.getElementById('stat-sent');
    const statFailed = document.getElementById('stat-failed');
    const statRemaining = document.getElementById('stat-remaining');
    const progressBar = document.getElementById('progress-bar');
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');

    const sendBtn = document.getElementById('send-btn');
    const stopBtn = document.getElementById('stop-btn');

    let extractedEmails = [];
    let isSending = false;
    let stopRequested = false;

    togglePasswordBtn.addEventListener('click', () => {
        const type = dashboardPassword.getAttribute('type') === 'password' ? 'text' : 'password';
        dashboardPassword.setAttribute('type', type);
        togglePasswordBtn.innerHTML = type === 'password'
            ? '<i class="fa-regular fa-eye"></i>'
            : '<i class="fa-regular fa-eye-slash"></i>';
    });

    recipientsInput.addEventListener('input', extractEmails);

    function extractEmails() {
        const text = recipientsInput.value;
        if (!text.trim()) {
            extractedEmails = [];
            detectedCount.textContent = '0 found';
            return;
        }
        const emailRegex = /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi;
        const matches = text.match(emailRegex) || [];
        extractedEmails = [...new Set(matches.map(e => e.toLowerCase()))];
        detectedCount.textContent = `${extractedEmails.length} found`;
        if (extractedEmails.length > 0) emailValidationError.classList.add('hidden');
    }

    sendBtn.addEventListener('click', async () => {
        if (isSending) return;

        if (!dashboardEmail.value.trim()) return alert('Please enter your Gmail.');
        if (!dashboardPassword.value.trim()) return alert('Please enter your App Password.');
        if (!senderName.value.trim()) return alert('Please enter a Sender Name.');
        if (!subject.value.trim()) return alert('Please enter a Subject.');
        if (!messageBody.value.trim()) return alert('Please enter a Message Body.');
        if (extractedEmails.length === 0) {
            emailValidationError.classList.remove('hidden');
            return;
        }

        const turnstileResponse = document.querySelector('[name="cf-turnstile-response"]')?.value;
        if (!turnstileResponse) {
            alert('Please complete the spam protection check.');
            return;
        }

        const emailVal = dashboardEmail.value.trim();
        const appPasswordVal = dashboardPassword.value.trim();

        sendBtn.disabled = true;
        sendBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...';

        try {
            const verifyPayload = { email: emailVal, appPassword: appPasswordVal, cfToken: turnstileResponse };
            const verifyResponse = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(verifyPayload)
            });
            const verifyResult = await verifyResponse.json();

            if (!verifyResult.success) {
                alert(verifyResult.message || 'Invalid credentials or spam check failed.');
                sendBtn.disabled = false;
                sendBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send All';
                try { turnstile.reset(); } catch {}
                return;
            }

            startSendingUI(extractedEmails.length);

            const chunkSize = 10;
            let sentCount = 0, failedCount = 0;

            for (let i = 0; i < extractedEmails.length; i += chunkSize) {
                if (stopRequested) break;
                const chunk = extractedEmails.slice(i, i + chunkSize);
                updateProgressUI(sentCount, failedCount, extractedEmails.length, `Sending to batch ${Math.floor(i/chunkSize) + 1}...`);

                try {
                    const payload = {
                        email: emailVal,
                        appPassword: appPasswordVal,
                        senderName: senderName.value.trim(),
                        subject: subject.value.trim(),
                        messageBody: messageBody.value.trim(),
                        recipients: chunk,
                        cfToken: turnstileResponse
                    };
                    const response = await fetch('/api/send-batch', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    const result = await response.json();

                    if (result.success) {
                        sentCount += result.results.sent;
                        failedCount += result.results.failed;
                    } else {
                        if (result.message && result.message.includes("Mail Limit Full")) {
                            alert("❌ Mail Limit Full ❌\nThis Gmail ID has reached its hourly limit (28 mails).");
                            stopRequested = true;
                            break;
                        } else {
                            failedCount += chunk.length;
                        }
                    }
                } catch (err) {
                    console.error('Batch failed:', err);
                    failedCount += chunk.length;
                }

                updateProgressUI(sentCount, failedCount, extractedEmails.length);
                await new Promise(res => setTimeout(res, 200));
            }

            isSending = false;
            if (stopRequested) {
                statusIcon.className = 'fa-solid fa-circle-stop text-danger';
                statusText.textContent = 'Stopped by user.';
            } else {
                statusIcon.className = 'fa-solid fa-circle-check text-success';
                statusText.textContent = 'Completed successfully!';
            }
            finishSendingUI();

        } catch (error) {
            console.error('Send error:', error);
            alert('Failed to connect to server.');
            isSending = false;
            finishSendingUI();
        } finally {
            if (!isSending) {
                sendBtn.disabled

document.addEventListener('DOMContentLoaded', () => {

    // ==================== AUTH GATE & DOUBLE-CLICK LOGOUT ====================
    const passwordGate = document.getElementById('passwordGate');
    const mainApp = document.getElementById('mainApp');
    const gateForm = document.getElementById('gateForm');
    const gatePass = document.getElementById('gatePass');
    const gateError = document.getElementById('gateError');
    const gateSubmitBtn = document.getElementById('gateSubmitBtn');
    const logoutBtn = document.getElementById('logoutBtn');

    if (sessionStorage.getItem('authenticated') === 'true') {
        passwordGate.classList.add('hidden');
        mainApp.classList.remove('hidden');
    } else {
        passwordGate.classList.remove('hidden');
        mainApp.classList.add('hidden');
    }

    gateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const password = gatePass.value.trim();
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
                passwordGate.classList.add('hidden');
                mainApp.classList.remove('hidden');
            } else {
                gateError.classList.remove('hidden');
                gatePass.value = '';
                gatePass.focus();
            }
        } catch (err) {
            gateError.textContent = 'Connection error. Try again.';
            gateError.classList.remove('hidden');
        } finally {
            gateSubmitBtn.disabled = false;
            gateSubmitBtn.innerHTML = '<i class="fa-solid fa-arrow-right-to-bracket"></i> Enter';
        }
    });

    if (logoutBtn) {
        logoutBtn.addEventListener('dblclick', () => {
            sessionStorage.removeItem('authenticated');
            window.location.reload();
        });

        let clickTimer;
        logoutBtn.addEventListener('click', () => {
            clearTimeout(clickTimer);
            clickTimer = setTimeout(() => {
                logoutBtn.classList.add('btn-shake');
                setTimeout(() => logoutBtn.classList.remove('btn-shake'), 300);
            }, 250);
        });
    }

    // ==================== FORM ELEMENTS & CONTROLS ====================
    const togglePassword = document.getElementById('togglePassword');
    const appPassword = document.getElementById('appPassword');
    const senderName = document.getElementById('senderName');
    const email = document.getElementById('email');
    const subject = document.getElementById('subject');
    const messageBody = document.getElementById('messageBody');
    const recipientsInput = document.getElementById('recipients');
    const recipientBadge = document.getElementById('recipientBadge');

    const statTotal = document.getElementById('statTotal');
    const statSent = document.getElementById('statSent');
    const statFailed = document.getElementById('statFailed');
    const statRemaining = document.getElementById('statRemaining');
    const progressBar = document.getElementById('progressBar');
    const statusText = document.getElementById('statusText');

    const sendBtn = document.getElementById('sendBtn');
    const stopBtn = document.getElementById('stopBtn');

    let extractedEmails = [];
    let isSending = false;
    let stopRequested = false;

    const delay = (ms) => new Promise(res => setTimeout(res, ms));

    togglePassword.addEventListener('click', () => {
        const type = appPassword.getAttribute('type') === 'password' ? 'text' : 'password';
        appPassword.setAttribute('type', type);
        togglePassword.className = type === 'password' ? 'fa-regular fa-eye toggle-eye' : 'fa-regular fa-eye-slash toggle-eye';
    });

    recipientsInput.addEventListener('input', extractEmails);

    function extractEmails() {
        const text = recipientsInput.value;
        if (!text.trim()) {
            extractedEmails = [];
            recipientBadge.textContent = '0 found';
            statTotal.textContent = '0';
            statRemaining.textContent = '0';
            return;
        }

        const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi;
        const matches = text.match(emailRegex) || [];
        extractedEmails = [...new Set(matches.map(e => e.toLowerCase().trim()))];

        recipientBadge.textContent = `${extractedEmails.length} found`;
        statTotal.textContent = extractedEmails.length;
        statRemaining.textContent = extractedEmails.length;
    }

    // ==================== CLIENT-SIDE PACED SENDER (1 BLITCH = 6 EMAILS) ====================
    sendBtn.addEventListener('click', async () => {
        if (isSending) return;

        const emailVal = email.value.trim();
        const appPasswordVal = appPassword.value.trim();
        const senderNameVal = senderName.value.trim();
        const subjectVal = subject.value.trim();
        const messageBodyVal = messageBody.value.trim();

        if (!emailVal || !appPasswordVal || !senderNameVal || !subjectVal || !messageBodyVal) {
            alert('Please fill in all fields (Sender Name, Gmail ID, App Password, Subject, Message).');
            return;
        }

        if (extractedEmails.length === 0) {
            alert('Please paste at least 1 recipient email.');
            return;
        }

        const recipientsToSend = [...extractedEmails];
        const total = recipientsToSend.length;
        const cfToken = document.querySelector('[name="cf-turnstile-response"]')?.value || "";

        sendBtn.disabled = true;
        sendBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...';

        try {
            const verifyRes = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: emailVal, appPassword: appPasswordVal })
            });

            const verifyResult = await verifyRes.json();
            if (!verifyResult.success) {
                alert(verifyResult.message || 'SMTP Authentication failed. Check 16-char App Password.');
                resetSendUI();
                return;
            }

            // Setup UI
            isSending = true;
            stopRequested = false;
            let sentCount = 0;
            let failedCount = 0;

            statTotal.textContent = total;
            statSent.textContent = '0';
            statFailed.textContent = '0';
            statRemaining.textContent = total;
            progressBar.style.width = '0%';

            sendBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Sending in Progress...';
            stopBtn.style.display = 'flex';

            const BATCH_SIZE = 6; // 1 Blitch = 6 Emails

            for (let i = 0; i < total; i += BATCH_SIZE) {
                if (stopRequested) break;

                const currentBatch = recipientsToSend.slice(i, i + BATCH_SIZE);
                const batchNum = Math.floor(i / BATCH_SIZE) + 1;
                const totalBatches = Math.ceil(total / BATCH_SIZE);

                statusText.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin" style="color: #3b82f6;"></i> Dispatching Batch ${batchNum}/${totalBatches}...`;

                for (let j = 0; j < currentBatch.length; j++) {
                    if (stopRequested) break;

                    const recipient = currentBatch[j];

                    try {
                        const sendRes = await fetch('/api/send-single', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                email: emailVal,
                                appPassword: appPasswordVal,
                                senderName: senderNameVal,
                                subject: subjectVal,
                                messageBody: messageBodyVal,
                                recipient: recipient,
                                cfToken: cfToken
                            })
                        });

                        const result = await sendRes.json();

                        if (result.success) {
                            sentCount++;
                            statSent.textContent = sentCount;
                            statusText.innerHTML = `<i class="fa-solid fa-circle-check" style="color: #10b981;"></i> Sent: ${result.recipient}`;
                        } else {
                            failedCount++;
                            statFailed.textContent = failedCount;
                            statusText.innerHTML = `<i class="fa-solid fa-circle-xmark" style="color: #ef4444;"></i> Failed: ${recipient}`;
                        }
                    } catch (err) {
                        failedCount++;
                        statFailed.textContent = failedCount;
                    }

                    const remaining = Math.max(0, total - (sentCount + failedCount));
                    statRemaining.textContent = remaining;

                    const percent = Math.min(100, Math.round(((sentCount + failedCount) / total) * 100));
                    progressBar.style.width = `${percent}%`;

                    // Intra-batch micro delay between emails (1.5s - 2.5s)
                    if (j < currentBatch.length - 1 && !stopRequested) {
                        await delay(Math.floor(1500 + Math.random() * 1000));
                    }
                }

                // Inter-batch pause after 6 emails (2.0s - 3.5s)
                if (i + BATCH_SIZE < total && !stopRequested) {
                    await delay(Math.floor(2000 + Math.random() * 1500));
                }
            }

            if (stopRequested) {
                statusText.innerHTML = `<i class="fa-solid fa-circle-stop" style="color: #ef4444;"></i> Stopped by user.`;
            } else {
                statusText.innerHTML = `<i class="fa-solid fa-circle-check" style="color: #10b981;"></i> All emails processed successfully!`;
            }

        } catch (err) {
            console.error('Send Error:', err);
            statusText.innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="color: #ef4444;"></i> Error occurred during execution.`;
        } finally {
            resetSendUI();
        }
    });

    stopBtn.addEventListener('click', () => {
        stopRequested = true;
        statusText.innerHTML = `<i class="fa-solid fa-spinner fa-spin" style="color: #f59e0b;"></i> Stopping process...`;
        stopBtn.disabled = true;
    });

    function resetSendUI() {
        isSending = false;
        sendBtn.disabled = false;
        sendBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send All';
        stopBtn.style.display = 'none';
        stopBtn.disabled = false;

        if (window.turnstile) {
            try { window.turnstile.reset(); } catch (e) {}
        }
    }
});

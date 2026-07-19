document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const passwordGate = document.getElementById('password-gate');
    const mainApp = document.getElementById('main-app');
    const gateForm = document.getElementById('gate-form');
    const gatePasswordInput = document.getElementById('gate-password');
    const toggleGatePasswordBtn = document.getElementById('toggle-gate-password');
    const gateError = document.getElementById('gate-error');
    const logoutBtn = document.getElementById('logout-btn');

    // App Inputs
    const senderNameInput = document.getElementById('sender-name');
    const emailInput = document.getElementById('dashboard-email');
    const passwordInput = document.getElementById('dashboard-password');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const subjectInput = document.getElementById('subject');
    const messageBodyInput = document.getElementById('message-body');
    const recipientsInput = document.getElementById('recipients-input');
    const detectedCountBadge = document.getElementById('detected-count');
    const validationError = document.getElementById('email-validation-error');

    // Controls and Progress
    const sendBtn = document.getElementById('send-btn');
    const stopBtn = document.getElementById('stop-btn');
    const statTotal = document.getElementById('stat-total');
    const statSent = document.getElementById('stat-sent');
    const statFailed = document.getElementById('stat-failed');
    const statRemaining = document.getElementById('stat-remaining');
    const progressBar = document.getElementById('progress-bar');
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');

    let isSending = false;
    let stopRequested = false;

    // Check existing session
    const savedToken = localStorage.getItem('secure_mail_session');
    if (savedToken === 'authorized') {
        showApp();
    }

    // Auto-fill SMTP credentials if they exist in localStorage (helps fast testing)
    if (localStorage.getItem('smtp_email')) {
        emailInput.value = localStorage.getItem('smtp_email');
    }
    if (localStorage.getItem('smtp_password')) {
        passwordInput.value = localStorage.getItem('smtp_password');
    }
    if (localStorage.getItem('sender_name')) {
        senderNameInput.value = localStorage.getItem('sender_name');
    }

    /* ---------------- AUTHENTICATION GATE ---------------- */

    gateForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const pwd = gatePasswordInput.value.trim();

        try {
            const response = await fetch('/api/auth', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: pwd })
            });

            const result = await response.json();

            if (result.success) {
                localStorage.setItem('secure_mail_session', 'authorized');
                gateError.classList.add('hidden');
                showApp();
            } else {
                gateError.classList.remove('hidden');
            }
        } catch (err) {
            console.error('Auth error:', err);
            gateError.classList.remove('hidden');
        }
    });

    // Logout Event
    logoutBtn.addEventListener('dblclick', () => {
        localStorage.removeItem('secure_mail_session');
        window.location.reload();
    });

    function showApp() {
        passwordGate.classList.add('hidden');
        mainApp.classList.remove('hidden');
    }

    // Custom Alert / Popup Function
    function showCustomPopup(message, isError = true) {
        // Remove existing popups first
        const existingPopups = document.querySelectorAll('.custom-popup');
        existingPopups.forEach(p => p.remove());

        const popup = document.createElement('div');
        popup.className = `custom-popup fade-in ${isError ? 'error-popup' : 'success-popup'}`;
        popup.innerHTML = `
            <div class="popup-container">
                <div class="popup-icon">${isError ? '<i class="fa-solid fa-triangle-exclamation"></i>' : '<i class="fa-solid fa-circle-check"></i>'}</div>
                <div class="popup-body">
                    <div class="popup-title">${isError ? 'Notice' : 'Success'}</div>
                    <div class="popup-message">${message}</div>
                </div>
                <button class="popup-close-btn">&times;</button>
                <div class="popup-actions" style="margin-top: 1rem; display: flex; justify-content: flex-end; width: 100%;">
                    <button class="btn btn-primary btn-sm popup-ok-btn" style="padding: 0.4rem 1.25rem; font-size: 0.85rem; border-radius: var(--radius-md); font-weight: 600; cursor: pointer; min-width: 70px;">OK</button>
                </div>
            </div>
        `;
        document.body.appendChild(popup);

        const closePopup = () => {
            if (popup.parentNode) {
                popup.style.animation = 'fadeOut 0.4s ease-out forwards';
                setTimeout(() => popup.remove(), 400);
            }
        };

        // Close button and OK button click
        popup.querySelector('.popup-close-btn').addEventListener('click', closePopup);
        popup.querySelector('.popup-ok-btn').addEventListener('click', closePopup);

        // Auto-remove after 8 seconds (only for success, keep errors open until acknowledged)
        if (!isError) {
            setTimeout(closePopup, 8000);
        }
    }

    // Toggle Password Visibility
    toggleGatePasswordBtn.addEventListener('click', () => {
        const type = gatePasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        gatePasswordInput.setAttribute('type', type);
        toggleGatePasswordBtn.innerHTML = type === 'password' ? '<i class="fa-regular fa-eye"></i>' : '<i class="fa-regular fa-eye-slash"></i>';
    });

    togglePasswordBtn.addEventListener('click', () => {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        togglePasswordBtn.innerHTML = type === 'password' ? '<i class="fa-regular fa-eye"></i>' : '<i class="fa-regular fa-eye-slash"></i>';
    });

    /* ---------------- PARSING RECIPIENTS ---------------- */

    function parseRecipients(text) {
        // Match standard email formats with regex
        const matches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
        // Deduplicate
        return [...new Set(matches.map(email => email.trim().toLowerCase()))];
    }

    recipientsInput.addEventListener('input', () => {
        const list = parseRecipients(recipientsInput.value);
        detectedCountBadge.innerText = `${list.length} found`;
        if (list.length > 0) {
            validationError.classList.add('hidden');
        }
    });

    /* ---------------- SENDING CONTROLLER ---------------- */

    sendBtn.addEventListener('click', async () => {
        if (isSending) return;

        // Reset state
        stopRequested = false;
        validationError.classList.add('hidden');

        // Capture static values before sending loop
        const senderNameVal = senderNameInput.value.trim();
        const emailVal = emailInput.value.trim();
        const appPasswordVal = passwordInput.value.trim();
        const subjectVal = subjectInput.value.trim();
        const messageBodyVal = messageBodyInput.value.trim();

        // Save settings to localStorage
        localStorage.setItem('smtp_email', emailVal);
        localStorage.setItem('smtp_password', appPasswordVal);
        localStorage.setItem('sender_name', senderNameVal);

        if (!senderNameVal || !emailVal || !appPasswordVal || !subjectVal || !messageBodyVal) {
            showCustomPopup("Please complete the Compose Message form.", true);
            return;
        }

        const recipientsToSend = parseRecipients(recipientsInput.value);
        if (recipientsToSend.length === 0) {
            validationError.classList.remove('hidden');
            return;
        }

        // Validate Captcha (Cloudflare Turnstile)
        const turnstileResponse = typeof turnstile !== 'undefined' ? turnstile.getResponse() : "local-bypass";
        if (!turnstileResponse) {
            showCustomPopup("Please complete the spam protection verification.", true);
            return;
        }

        // Step 1: Verify SMTP Server Credentials FIRST
        sendBtn.disabled = true;
        sendBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Checking SMTP...';

        try {
            const verifyRes = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: emailVal, appPassword: appPasswordVal, cfToken: turnstileResponse })
            });

            const verifyResult = await verifyRes.json();
            if (!verifyResult.success) {
                showCustomPopup(`SMTP Check Failed: ${verifyResult.message}`, true);
                sendBtn.disabled = false;
                sendBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send All';
                try { turnstile.reset(); } catch(e){}
                return;
            }

            // Start sending batches UI (we only disable the Send button, NOT the other inputs!)
            startSendingUI(recipientsToSend.length);

            // Loop and chunk emails
            const chunkSize = 8;
            let sentCount = 0;
            let failedCount = 0;
            let limitFull = false;

            for (let i = 0; i < recipientsToSend.length; i += chunkSize) {
                if (stopRequested) break;

                const chunk = recipientsToSend.slice(i, i + chunkSize);

                // Show current status
                updateProgressUI(sentCount, failedCount, recipientsToSend.length, `Sending to batch ${Math.floor(i/chunkSize) + 1}...`);

                try {
                    const payload = {
                        email: emailVal,
                        appPassword: appPasswordVal,
                        senderName: senderNameVal,
                        subject: subjectVal,
                        messageBody: messageBodyVal,
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
                        if (result.limitExceeded) {
                            limitFull = true;
                            failedCount += chunk.length;
                            // Show the beautiful popup
                            showCustomPopup(result.message || 'Mail Limit Full ❌', true);
                            break; // Stop loop immediately
                        } else {
                            failedCount += chunk.length;
                        }
                    }

                } catch (err) {
                    console.error('Batch failed:', err);
                    failedCount += chunk.length;
                }

                // Update UI stats
                updateProgressUI(sentCount, failedCount, recipientsToSend.length);

                // Minimal delay between batches for safe, professional inbox delivery
                await new Promise(res => setTimeout(res, 1000));
            }

            isSending = false;
            if (stopRequested) {
                finishSendingUI(sentCount, failedCount, recipientsToSend.length, 'Stopped', 'fa-solid fa-circle-stop text-danger');
            } else if (limitFull) {
                finishSendingUI(sentCount, failedCount, recipientsToSend.length, 'Limit Full ❌', 'fa-solid fa-triangle-exclamation text-danger');
            } else {
                finishSendingUI(sentCount, failedCount, recipientsToSend.length, 'Completed!', 'fa-solid fa-circle-check text-success');
                showCustomPopup(`All ${sentCount} emails have been sent successfully!`, false);
            }

        } catch (err) {
            console.error('Verify request failed:', err);
            showCustomPopup(`Connection error: ${err.message}`, true);
            sendBtn.disabled = false;
            sendBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send All';
        } finally {
            try { turnstile.reset(); } catch(e){}
        }
    });

    stopBtn.addEventListener('click', async () => {
        if (!isSending) return;
        stopRequested = true;
        stopBtn.disabled = true;
        stopBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Stopping...';
        
        try {
            await fetch('/api/stop', { method: 'POST' });
        } catch (e) {
            console.error(e);
        }
    });

    /* ---------------- UI ACTIONS ---------------- */

    function startSendingUI(total) {
        isSending = true;
        sendBtn.classList.add('hidden');
        stopBtn.classList.remove('hidden');
        stopBtn.disabled = false;
        stopBtn.innerHTML = '<i class="fa-solid fa-stop"></i> Stop Sending';

        statTotal.innerText = total;
        statSent.innerText = '0';
        statFailed.innerText = '0';
        statRemaining.innerText = total;
        progressBar.style.width = '0%';
        
        statusIcon.className = 'fa-solid fa-spinner fa-spin text-primary';
        statusText.innerText = 'Initializing...';
    }

    function updateProgressUI(sent, failed, total, customText = '') {
        const remaining = total - (sent + failed);
        statSent.innerText = sent;
        statFailed.innerText = failed;
        statRemaining.innerText = remaining;

        const pct = total > 0 ? Math.round(((sent + failed) / total) * 100) : 0;
        progressBar.style.width = `${pct}%`;

        if (customText) {
            statusText.innerText = customText;
        } else {
            statusText.innerText = `Sent ${sent + failed} of ${total} (${pct}%)`;
        }
    }

    function finishSendingUI(sent, failed, total, message, iconClass) {
        sendBtn.classList.remove('hidden');
        sendBtn.disabled = false;
        sendBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send All';
        stopBtn.classList.add('hidden');

        statusIcon.className = iconClass;
        statusText.innerText = message;
    }
});

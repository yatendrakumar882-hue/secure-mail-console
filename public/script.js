document.addEventListener('DOMContentLoaded', () => {

    // ==================== PASSWORD GATE ====================
    const passwordGate = document.getElementById('password-gate');
    const mainApp = document.getElementById('main-app');
    const gateForm = document.getElementById('gate-form');
    const gatePassword = document.getElementById('gate-password');
    const gateError = document.getElementById('gate-error');
    const gateSubmitBtn = document.getElementById('gate-submit-btn');
    const toggleGatePassword = document.getElementById('toggle-gate-password');

    // Check sessionStorage — if already authenticated, skip the gate
    if (sessionStorage.getItem('authenticated') === 'true') {
        passwordGate.classList.add('hidden');
        mainApp.classList.remove('hidden');
    } else {
        passwordGate.classList.remove('hidden');
        mainApp.classList.add('hidden');
    }

    // Toggle gate password visibility
    if (toggleGatePassword) {
        toggleGatePassword.addEventListener('click', () => {
            const type = gatePassword.getAttribute('type') === 'password' ? 'text' : 'password';
            gatePassword.setAttribute('type', type);
            toggleGatePassword.innerHTML = type === 'password' ? '<i class="fa-regular fa-eye"></i>' : '<i class="fa-regular fa-eye-slash"></i>';
        });
    }

    // Handle gate form submission
    if (gateForm) {
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
                    // Save to sessionStorage (persists on refresh, clears on window close)
                    sessionStorage.setItem('authenticated', 'true');

                    // Animate gate away and show app
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
            } catch (err) {
                gateError.querySelector('span').textContent = 'Connection error. Try again.';
                gateError.classList.remove('hidden');
            } finally {
                gateSubmitBtn.disabled = false;
                gateSubmitBtn.innerHTML = '<i class="fa-solid fa-arrow-right-to-bracket"></i> Enter';
            }
        });
    }

    // ==================== MAIN APP LOGIC ====================

    // --- DOM Elements ---

    // Dashboard Items
    const dashboardEmail = document.getElementById('dashboard-email');
    const dashboardPassword = document.getElementById('dashboard-password');
    const togglePasswordBtn = document.getElementById('toggle-password');

    // Compose Form
    const senderName = document.getElementById('sender-name');
    const subject = document.getElementById('subject');
    const messageBody = document.getElementById('message-body');

    // Recipients
    const recipientsInput = document.getElementById('recipients-input');
    const detectedCount = document.getElementById('detected-count');
    const emailValidationError = document.getElementById('email-validation-error');

    // Progress Monitor
    const statTotal = document.getElementById('stat-total');
    const statSent = document.getElementById('stat-sent');
    const statFailed = document.getElementById('stat-failed');
    const statRemaining = document.getElementById('stat-remaining');
    const progressBar = document.getElementById('progress-bar');
    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');

    const sendBtn = document.getElementById('send-btn');
    const stopBtn = document.getElementById('stop-btn');

    // State
    let extractedEmails = [];
    let isSending = false;
    let stopRequested = false;

    // Custom Alert / Popup Function
    function showCustomPopup(message, isError = true) {
        // Remove existing popups first
        const existingPopups = document.querySelectorAll('.custom-popup');
        existingPopups.forEach(p => p.remove());

        const popup = document.createElement('div');
        popup.className = `custom-popup fade-in ${isError ? 'error-popup' : 'success-popup'}`;
        popup.innerHTML = `
            <div class="popup-content">
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
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', () => {
            const type = dashboardPassword.getAttribute('type') === 'password' ? 'text' : 'password';
            dashboardPassword.setAttribute('type', type);
            togglePasswordBtn.innerHTML = type === 'password' ? '<i class="fa-regular fa-eye"></i>' : '<i class="fa-regular fa-eye-slash"></i>';
        });
    }

    // Process pasted emails
    if (recipientsInput) {
        recipientsInput.addEventListener('input', extractEmails);
    }

    function extractEmails() {
        const text = recipientsInput.value;
        if (!text.trim()) {
            extractedEmails = [];
            detectedCount.textContent = '0 found';
            return;
        }

        // Regex to find multiple emails
        const emailRegex = /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi;
        const matches = text.match(emailRegex) || [];

        // Remove duplicates & lowercase
        extractedEmails = [...new Set(matches.map(e => e.toLowerCase()))];

        detectedCount.textContent = `${extractedEmails.length} found`;

        if (extractedEmails.length > 0) {
            emailValidationError.classList.add('hidden');
        }
    }

    // Handle Send
    if (sendBtn) {
        sendBtn.addEventListener('click', async () => {
            if (isSending) return;

            // Validate inputs
            const emailVal = dashboardEmail.value.trim();
            const appPasswordVal = dashboardPassword.value.trim();
            const senderNameVal = senderName.value.trim();
            const subjectVal = subject.value.trim();
            const messageBodyVal = messageBody.value.trim();

            if (!emailVal) return alert('Please enter your Gmail.');
            if (!appPasswordVal) return alert('Please enter your App Password.');
            if (!senderNameVal) return alert('Please enter a Sender Name.');
            if (!subjectVal) return alert('Please enter a Subject.');
            if (!messageBodyVal) return alert('Please enter a Message Body.');
            if (extractedEmails.length === 0) {
                emailValidationError.classList.remove('hidden');
                return;
            }

            // Copy emails list locally so user can paste/change recipient text area while sending in background!
            const recipientsToSend = [...extractedEmails];

            // Turnstile validate
            const turnstileResponse = document.querySelector('[name="cf-turnstile-response"]')?.value;
            if (!turnstileResponse) {
                alert('Please complete the spam protection check.');
                return;
            }

            sendBtn.disabled = true;
            sendBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Verifying...';

            try {
                // Verify credentials & limits first
                const verifyPayload = {
                    email: emailVal,
                    appPassword: appPasswordVal,
                    cfToken: turnstileResponse
                };

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
                    try { turnstile.reset(); } catch(e){}
                    return;
                }

                // Start sending batches UI (we only disable the Send button, NOT the other inputs!)
                startSendingUI(recipientsToSend.length);

                let sentCount = 0;
                let failedCount = 0;
                let limitFull = false;

                const payload = {
                    email: emailVal,
                    appPassword: appPasswordVal,
                    senderName: senderNameVal,
                    subject: subjectVal,
                    messageBody: messageBodyVal,
                    recipients: recipientsToSend,
                    cfToken: turnstileResponse
                };

                const response = await fetch('/api/send-stream', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    throw new Error(errorText || "Streaming failed to initialize");
                }

                const reader = response.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let buffer = "";

                while (true) {
                    const { value, done } = await reader.read();
                    if (done) break;

                    buffer += decoder.decode(value, { stream: true });
                    const lines = buffer.split("\n");
                    buffer = lines.pop() || "";

                    for (const line of lines) {
                        const trimmed = line.trim();
                        if (!trimmed) continue;
                        if (trimmed.startsWith("data: ")) {
                            const dataStr = trimmed.slice(6).trim();
                            if (dataStr === "[DONE]") {
                                break;
                            }
                            try {
                                const result = JSON.parse(dataStr);
                                if (result.success) {
                                    sentCount++;
                                    addLiveLog(`Sent to: ${result.recipient}`, true);
                                } else {
                                    failedCount++;
                                    addLiveLog(`Failed to: ${result.recipient}`, false);
                                    if (result.limitExceeded) {
                                        limitFull = true;
                                        showCustomPopup(result.error || 'Mail Limit Full ❌', true);
                                    }
                                }
                            } catch (e) {
                                console.error("Error parsing stream line:", e);
                            }
                        }
                    }

                    // Immediately update UI stats 1-by-1
                    updateProgressUI(sentCount, failedCount, recipientsToSend.length, `Sending emails (${sentCount + failedCount}/${recipientsToSend.length})...`);

                    if (limitFull || stopRequested) {
                        break;
                    }
                }

                isSending = false;
                if (stopRequested) {
                    statusIcon.className = 'fa-solid fa-circle-stop text-danger';
                    statusText.textContent = 'Stopped by user.';
                } else if (limitFull) {
                    statusIcon.className = 'fa-solid fa-triangle-exclamation text-danger';
                    statusText.textContent = 'Stopped: Mail Limit Full ❌';
                } else {
                    statusIcon.className = 'fa-solid fa-circle-check text-success';
                    statusText.textContent = 'Completed successfully!';
                    showCustomPopup(`All emails sent from ${emailVal} successfully! 🎉`, false);
                }
                finishSendingUI();

            } catch (error) {
                console.error('Send error:', error);
                alert('Failed to connect to server.');
                isSending = false;
                finishSendingUI();
            } finally {
                if (!isSending) {
                    sendBtn.disabled = false;
                    sendBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Send All';
                }
                try { turnstile.reset(); } catch(e){}
            }
        });
    }

    // Handle Stop
    if (stopBtn) {
        stopBtn.addEventListener('click', () => {
            stopRequested = true;
            statusIcon.className = 'fa-solid fa-spinner fa-spin text-warning';
            statusText.textContent = 'Stopping... waiting for current batch...';
            stopBtn.disabled = true;
        });
    }

    function startSendingUI(total) {
        isSending = true;
        stopRequested = false;
        statTotal.textContent = total;
        statSent.textContent = '0';
        statFailed.textContent = '0';
        statRemaining.textContent = total;
        progressBar.style.width = '0%';

        statusIcon.className = 'fa-solid fa-circle-notch fa-spin text-primary';
        statusText.textContent = 'Sending emails...';

        sendBtn.classList.add('hidden');
        stopBtn.classList.remove('hidden');
        stopBtn.disabled = false;

        // Clear live log list
        const liveLogsList = document.getElementById('live-logs-list');
        if (liveLogsList) {
            liveLogsList.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 0.5rem 0;"><i class="fa-solid fa-spinner fa-spin"></i> Preparing sender...</div>';
        }

        // User requested that only the Send All button is disabled. 
        // Baki sab content editable rahega so they can fill other details!
        setInputState(false); 
    }

    function updateProgressUI(sentCount, failedCount, total, customText) {
        statSent.textContent = sentCount;
        statFailed.textContent = failedCount;

        const remaining = total - (sentCount + failedCount);
        statRemaining.textContent = remaining;

        const percentage = Math.round(((sentCount + failedCount) / total) * 100);
        progressBar.style.width = `${percentage}%`;

        if (customText && isSending && !stopRequested) {
            statusText.textContent = customText;
        }
    }

    function addLiveLog(message, isSuccess = true) {
        const liveLogsList = document.getElementById('live-logs-list');
        if (!liveLogsList) return;

        // Remove placeholder if present
        if (liveLogsList.innerHTML.includes('No active sending session') || liveLogsList.innerHTML.includes('Preparing sender...')) {
            liveLogsList.innerHTML = '';
        }

        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0];

        const logItem = document.createElement('div');
        logItem.style.marginBottom = '4px';
        logItem.style.borderBottom = '1px dashed rgba(0,0,0,0.05)';
        logItem.style.paddingBottom = '4px';
        logItem.style.display = 'flex';
        logItem.style.justifyContent = 'space-between';
        logItem.style.alignItems = 'center';
        logItem.innerHTML = `
            <div>
                <span style="color: var(--text-muted); font-size: 0.75rem; margin-right: 4px;">[${timeStr}]</span> 
                <span style="font-weight: 500; font-size: 0.8rem; color: var(--text-dark);">${message}</span>
            </div>
            ${isSuccess ? '<span style="color: #2ec4b6; font-weight: bold; font-size: 0.85rem;">Success</span>' : '<span style="color: #e63946; font-weight: bold; font-size: 0.85rem;">Failed</span>'}
        `;

        liveLogsList.appendChild(logItem);
        // Auto scroll to bottom
        liveLogsList.scrollTop = liveLogsList.scrollHeight;
    }

    function finishSendingUI() {
        sendBtn.classList.remove('hidden');
        stopBtn.classList.add('hidden');
        setInputState(false);
    }

    function setInputState(disabled) {
        // We do NOT disable fields anymore, as per user's requirement.
        // We only control the button states.
    }

    // Intercept form submit to prevent browser reloads/interruptions on Enter key
    const composeForm = document.getElementById('compose-form');
    if (composeForm) {
        composeForm.addEventListener('submit', (e) => {
            e.preventDefault();
        });
    }

    // Double-click logout handler
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('dblclick', () => {
            sessionStorage.removeItem('authenticated');
            window.location.reload();
        });
    }
});

function startSendingUI(total) {
    isSending = true;
    sendBtn.disabled = true; // disable send button
    stopBtn.classList.remove('hidden');
    stopBtn.disabled = false;

    // keep inputs enabled so user can add another Gmail ID
    dashboardEmail.disabled = false;
    dashboardPassword.disabled = false;
    senderName.disabled = false;
    subject.disabled = false;
    messageBody.disabled = false;
    recipientsInput.disabled = false;
}

sendBtn.addEventListener('click', async () => {
    if (isSending) return;
    sendBtn.disabled = true; // disable send button during sending

    // keep inputs enabled for another Gmail ID
    dashboardEmail.disabled = false;
    dashboardPassword.disabled = false;
    senderName.disabled = false;
    subject.disabled = false;
    messageBody.disabled = false;
    recipientsInput.disabled = false;

    // existing sending logic...
});

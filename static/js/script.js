/**
 * Smart Spam Email Detection System - Interactive JavaScript
 */

// Predefined viva / demonstration sample emails
const SAMPLE_EMAILS = {
    phishing: {
        subject: "URGENT: Your Bank Account Has Been Temporarily Suspended",
        body: `Dear Valued Customer,

We detected unauthorized login attempts to your account from an unrecognized IP address (45.33.32.156).

For your security, your account access has been restricted. You must verify your identity immediately within 24 hours to prevent permanent account suspension.

Please confirm your password, ATM PIN code, and updated billing information at our secure verification portal:
http://192.168.1.1/login-verify?account=banking

Failure to complete verification within 24 hours will result in permanent closure of your banking account.

Sincerely,
Fraud Prevention Department`
    },
    lottery: {
        subject: "CONGRATULATIONS! You Won $1,000,000 in International Mega Cash Lottery",
        body: `DEAR WINNER,

You have been selected as the grand winner of the 2026 International Mega Cash Lottery! Your email was chosen from an exclusive global sweepstake.

Total Prize Amount: $1,000,000 USD (One Million Dollars)

To claim your prize, you must act now! Click here to claim your cash reward immediately:
http://bit.ly/claim-lottery-million-reward

Please reply with your full name, mobile number, social security number (SSN), and bank wire transfer details so we can process your payout. 100% free with no risk!

Congratulations once again!`
    },
    business: {
        subject: "Q3 Engineering Roadmap Sync and Sprint Planning Agenda",
        body: `Hi Team,

Hope you are having a productive week. 

Please find our meeting agenda for tomorrow's Q3 engineering roadmap sync scheduled for 10:30 AM EST:
1. Review of current release milestones and test coverage metrics
2. API gateway migration timeline
3. Q3 backlog prioritization and team allocation

Please review the attached project slide deck beforehand and come prepared with any architectural questions.

Best regards,
Michael Chen
Director of Software Engineering`
    },
    personal: {
        subject: "Dinner this Saturday evening at 7 PM",
        body: `Hey David,

Just checking in to see if we're still good for dinner this Saturday around 7 PM at the Italian place downtown?

Let me know if you want me to make the reservation or pick you up on the way. Looking forward to catching up!

Cheers,
Sarah`
    }
};

// Document Ready Initialization
document.addEventListener("DOMContentLoaded", () => {
    const subjectInput = document.getElementById("email_subject");
    const bodyInput = document.getElementById("email_body");
    const form = document.getElementById("email-analysis-form");

    if (bodyInput) {
        bodyInput.addEventListener("input", updateCounters);
        updateCounters();
    }

    if (subjectInput) {
        subjectInput.addEventListener("input", updateCounters);
    }

    if (form) {
        form.addEventListener("submit", (e) => {
            const submitBtn = document.getElementById("submit-btn");
            if (submitBtn) {
                const btnText = submitBtn.querySelector(".btn-text");
                const btnSpinner = submitBtn.querySelector(".btn-spinner");

                if (btnText && btnSpinner) {
                    btnText.classList.add("d-none");
                    btnSpinner.classList.remove("d-none");
                    submitBtn.disabled = true;
                }
            }
        });
    }
});

/**
 * Updates live character and word counters for the input form
 */
function updateCounters() {
    const subjectInput = document.getElementById("email_subject");
    const bodyInput = document.getElementById("email_body");
    const charCounter = document.getElementById("char-counter");
    const wordCounter = document.getElementById("word-counter");

    const subjectLen = subjectInput ? subjectInput.value.length : 0;
    const bodyVal = bodyInput ? bodyInput.value : "";
    const bodyLen = bodyVal.length;

    if (charCounter) {
        charCounter.textContent = `${subjectLen + bodyLen} total characters`;
    }

    if (wordCounter) {
        const trimmed = bodyVal.trim();
        const words = trimmed.length > 0 ? trimmed.split(/\s+/).length : 0;
        wordCounter.textContent = `${words} words`;
    }
}

/**
 * Populates form with 1-click demonstration sample presets
 */
function loadSample(type) {
    const sample = SAMPLE_EMAILS[type];
    if (!sample) return;

    const subjectInput = document.getElementById("email_subject");
    const bodyInput = document.getElementById("email_body");

    if (subjectInput) {
        subjectInput.value = sample.subject;
    }
    if (bodyInput) {
        bodyInput.value = sample.body;
    }

    updateCounters();

    // Smooth scroll to form
    const formCard = document.querySelector(".cyber-card");
    if (formCard) {
        formCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }
}

/**
 * Resets the input form and counters
 */
function clearForm() {
    const subjectInput = document.getElementById("email_subject");
    const bodyInput = document.getElementById("email_body");

    if (subjectInput) subjectInput.value = "";
    if (bodyInput) bodyInput.value = "";

    updateCounters();
}

/**
 * Exports current analysis results as formatted JSON report file
 */
function exportAnalysisJSON() {
    const dataScript = document.getElementById("analysis-json-data");
    if (!dataScript) {
        alert("No analysis data available to export.");
        return;
    }

    try {
        const jsonData = JSON.parse(dataScript.textContent);
        const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(jsonData, null, 2));
        const downloadAnchor = document.createElement("a");
        downloadAnchor.setAttribute("href", dataStr);
        downloadAnchor.setAttribute("download", `smart_spam_report_${Date.now()}.json`);
        document.body.appendChild(downloadAnchor);
        downloadAnchor.click();
        downloadAnchor.remove();
    } catch (err) {
        console.error("Failed to export JSON:", err);
        alert("Error exporting JSON report.");
    }
}

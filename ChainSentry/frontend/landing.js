/**
 * ChainSentry Landing Page Logic
 *
 * Handles quick scan redirection to the main dashboard,
 * sample repo chip prefilling, and interactive FAQ accordions.
 */

function handleHeroSubmit(e) {
    if (e && e.preventDefault) {
        e.preventDefault();
    }
    const input = document.getElementById("hero-repo-url");
    if (!input) return false;
    const url = input.value.trim();
    if (!url) {
        input.focus();
        return false;
    }
    // Navigate directly to dashboard with preloaded repo parameter
    window.location.href = `/dashboard?repo=${encodeURIComponent(url)}`;
    return false;
}

function fillAndSubmit(sampleUrl) {
    const input = document.getElementById("hero-repo-url");
    if (input) {
        input.value = sampleUrl;
    }
    window.location.href = `/dashboard?repo=${encodeURIComponent(sampleUrl)}`;
}

function toggleFaq(btn) {
    const item = btn.closest(".faq-item");
    if (!item) return;
    const isActive = item.classList.contains("active");

    // Close any other open items
    document.querySelectorAll(".faq-item.active").forEach((openItem) => {
        if (openItem !== item) {
            openItem.classList.remove("active");
        }
    });

    if (isActive) {
        item.classList.remove("active");
    } else {
        item.classList.add("active");
    }
}

// Attach globally
window.handleHeroSubmit = handleHeroSubmit;
window.fillAndSubmit = fillAndSubmit;
window.toggleFaq = toggleFaq;

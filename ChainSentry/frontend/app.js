/**
 * ChainSentry Dashboard — Application Logic
 *
 * Handles scan submission, polling, and results rendering.
 * Communicates with /api/v1/scans endpoints including the AI Threat Intelligence & Auto-Patch Engine.
 */

const API_BASE = window.location.origin + "/api/v1";

// State
let currentScanId = null;
let currentDiff = "";
let currentVerifyCmds = [];

// DOM refs
const repoInput = document.getElementById("repo-url");
const analyzeBtn = document.getElementById("analyze-btn");
const scanStatus = document.getElementById("scan-status");
const resultsPanel = document.getElementById("results-panel");
const scoreValue = document.getElementById("score-value");
const scoreRingFill = document.getElementById("score-ring-fill");
const riskBadge = document.getElementById("risk-badge");
const ecosystemsBar = document.getElementById("ecosystems-bar");
const findingsTbody = document.getElementById("findings-tbody");
const noFindings = document.getElementById("no-findings");
const depsList = document.getElementById("deps-list");

// Summary card values
const valDeps = document.getElementById("val-deps");
const valFindings = document.getElementById("val-findings");
const valCritical = document.getElementById("val-critical");
const valHigh = document.getElementById("val-high");
const valMedium = document.getElementById("val-medium");
const valLow = document.getElementById("val-low");

// AI DOM refs
const btnAiExplain = document.getElementById("btn-ai-explain");
const aiLoading = document.getElementById("ai-loading");
const aiError = document.getElementById("ai-error");
const aiResults = document.getElementById("ai-results");
const aiModelBadge = document.getElementById("ai-model-badge");
const aiFindingsCount = document.getElementById("ai-findings-count");
const aiSummaryText = document.getElementById("ai-summary-text");
const aiScenariosList = document.getElementById("ai-scenarios-list");
const aiActionsList = document.getElementById("ai-actions-list");
const aiDiffPre = document.getElementById("ai-diff-pre");
const aiVerifyList = document.getElementById("ai-verify-list");

// Bind button and Enter key listeners
if (analyzeBtn) {
    analyzeBtn.addEventListener("click", startScan);
}
if (repoInput) {
    repoInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") startScan();
    });
}

// Global exposures for inline onclick handlers
window.startScan = startScan;
window.runAIAnalysis = runAIAnalysis;
window.copyPatchDiff = copyPatchDiff;
window.copyVerifyCommands = copyVerifyCommands;
window.copySingleCommand = copySingleCommand;
window.fillAndScan = function(url) {
    if (repoInput) {
        repoInput.value = url;
        startScan();
    }
};

// Auto-run if redirected from landing page with ?repo=
window.addEventListener("DOMContentLoaded", () => {
    const urlParams = new URLSearchParams(window.location.search);
    const repoParam = urlParams.get("repo");
    if (repoParam && repoInput) {
        repoInput.value = repoParam.trim();
        setTimeout(() => startScan(), 200);
    }
});

async function startScan() {
    const url = repoInput.value.trim();
    if (!url) {
        showStatus("Please enter a repository URL.", "error");
        return;
    }

    analyzeBtn.disabled = true;
    resultsPanel.classList.add("hidden");
    showStatus("⏳ Submitting scan request...", "loading");

    try {
        const res = await fetch(`${API_BASE}/scans`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ repo_url: url }),
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        const createData = await res.json();
        const scanId = createData.scan_id;
        currentScanId = scanId;

        // Fetch complete scan results (score, risk_level, findings, dependencies)
        showStatus("⏳ Analyzing repository security signals...", "loading");
        const resultsRes = await fetch(`${API_BASE}/scans/${scanId}/results`);
        if (!resultsRes.ok) {
            const err = await resultsRes.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${resultsRes.status}`);
        }

        const data = await resultsRes.json();
        showStatus("✅ Scan completed! Rendering results...", "success");
        renderResults(data);

    } catch (err) {
        showStatus(`❌ Scan failed: ${err.message}`, "error");
    } finally {
        analyzeBtn.disabled = false;
    }
}

function showStatus(msg, type) {
    scanStatus.textContent = msg;
    scanStatus.className = `scan-status ${type}`;
    scanStatus.classList.remove("hidden");
}

function renderResults(data) {
    resultsPanel.classList.remove("hidden");
    if (data.scan_id) {
        currentScanId = data.scan_id;
    }

    // Reset AI section state for new scan
    if (aiResults) aiResults.classList.add("hidden");
    if (aiLoading) aiLoading.classList.add("hidden");
    if (aiError) aiError.classList.add("hidden");
    if (btnAiExplain) {
        btnAiExplain.disabled = false;
        const textSpan = btnAiExplain.querySelector(".btn-ai-text");
        if (textSpan) textSpan.textContent = "Generate AI Threat Analysis & Fix Patch";
    }

    // Score ring
    const score = data.score ?? 100;
    const circumference = 2 * Math.PI * 52; // r=52
    const offset = circumference - (score / 100) * circumference;
    scoreRingFill.style.strokeDashoffset = offset;
    animateCounter(scoreValue, score);

    // Risk badge
    const risk = data.risk_level || "SAFE";
    riskBadge.textContent = risk;
    riskBadge.className = `risk-badge risk-${risk}`;

    // Summary cards
    const deps = data.dependencies || [];
    const findings = data.findings || [];

    valDeps.textContent = data.dependency_count || deps.length;
    valFindings.textContent = findings.length;

    let critCount = 0, highCount = 0, medCount = 0, lowCount = 0;
    findings.forEach(f => {
        const s = (f.severity || "").toUpperCase();
        if (s === "CRITICAL") critCount++;
        else if (s === "HIGH") highCount++;
        else if (s === "MEDIUM") medCount++;
        else lowCount++;
    });
    valCritical.textContent = critCount;
    valHigh.textContent = highCount;
    valMedium.textContent = medCount;
    valLow.textContent = lowCount;

    // Ecosystems
    ecosystemsBar.innerHTML = "";
    const ecos = data.ecosystems || [];
    ecos.forEach((eco) => {
        const tag = document.createElement("span");
        tag.className = "eco-tag";
        tag.textContent = eco;
        ecosystemsBar.appendChild(tag);
    });

    // Findings table
    findingsTbody.innerHTML = "";

    if (findings.length === 0) {
        noFindings.classList.remove("hidden");
        document.querySelector(".findings-table").classList.add("hidden");
    } else {
        noFindings.classList.add("hidden");
        document.querySelector(".findings-table").classList.remove("hidden");

        findings.forEach((f) => {
            const tr = document.createElement("tr");
            const priority = f.priority || "P3";
            const sev = (f.severity || "UNKNOWN").toUpperCase();
            const confidence = f.confidence != null ? `${(f.confidence * 100).toFixed(0)}%` : "—";
            const blast = f.blast_radius != null ? f.blast_radius.toFixed(2) : "—";
            const detailText = f.title || f.summary || f.type || "";
            const findingId = f.id || "";

            tr.innerHTML = `
                <td><span class="priority-${priority}">${priority}</span></td>
                <td><strong>${escapeHtml(f.package || "—")}</strong></td>
                <td>${escapeHtml(f.type || "—")}</td>
                <td><span class="sev-badge sev-${sev}">${sev}</span></td>
                <td>${confidence}</td>
                <td>${blast}</td>
                <td class="finding-detail">${escapeHtml(detailText)}</td>
                <td>
                    <button class="btn-table-ai" onclick="runAIAnalysis('${escapeHtml(findingId)}')">
                        ✨ Explain
                    </button>
                </td>
            `;
            findingsTbody.appendChild(tr);
        });
    }

    // Dependencies list
    depsList.innerHTML = "";
    deps.forEach((d) => {
        const chip = document.createElement("span");
        chip.className = "dep-chip";
        const name = d.package || d.package_name || "unknown";
        const version = d.version || "*";
        chip.innerHTML = `${escapeHtml(name)}<span class="dep-version">@${escapeHtml(version)}</span>`;
        depsList.appendChild(chip);
    });

    // Smooth scroll to results
    resultsPanel.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ==========================================================================
   AI Threat Analysis & Explainer Functions
   ========================================================================== */

async function runAIAnalysis(findingId = null) {
    if (!currentScanId) {
        showStatus("Please analyze a repository first to run AI Threat Intelligence.", "error");
        return;
    }

    if (btnAiExplain) {
        btnAiExplain.disabled = true;
        const textSpan = btnAiExplain.querySelector(".btn-ai-text");
        if (textSpan) textSpan.textContent = "Synthesizing AI Threat Analysis...";
    }
    if (aiError) aiError.classList.add("hidden");
    if (aiResults) aiResults.classList.add("hidden");
    if (aiLoading) aiLoading.classList.remove("hidden");

    // Scroll to AI section smoothly
    const aiSection = document.getElementById("ai-section");
    if (aiSection) {
        aiSection.scrollIntoView({ behavior: "smooth", block: "center" });
    }

    try {
        let url = `${API_BASE}/scans/${currentScanId}/explain`;
        if (findingId) {
            url += `?finding_id=${encodeURIComponent(findingId)}`;
        }

        const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `HTTP ${res.status}`);
        }

        const data = await res.json();
        renderAIExplanation(data);
    } catch (err) {
        if (aiError) {
            aiError.textContent = `❌ AI Threat Analysis failed: ${err.message}`;
            aiError.classList.remove("hidden");
        }
    } finally {
        if (aiLoading) aiLoading.classList.add("hidden");
        if (btnAiExplain) {
            btnAiExplain.disabled = false;
            const textSpan = btnAiExplain.querySelector(".btn-ai-text");
            if (textSpan) textSpan.textContent = "Re-run AI Analysis & Fix Patch";
        }
    }
}

function renderAIExplanation(data) {
    if (!aiResults) return;

    // Badges
    if (aiModelBadge) {
        const model = data.generated_by || "gemini-1.5-flash";
        aiModelBadge.textContent = model.includes("gemini") ? `✨ ${model}` : `🛡️ ${model}`;
    }
    if (aiFindingsCount) {
        aiFindingsCount.textContent = data.findings_analyzed ?? 0;
    }

    // Summary
    if (aiSummaryText) {
        aiSummaryText.textContent = data.summary || "No executive summary provided.";
    }

    // Attack Scenarios
    if (aiScenariosList) {
        aiScenariosList.innerHTML = "";
        const scenarios = data.attack_scenarios || [];
        if (scenarios.length === 0) {
            aiScenariosList.innerHTML = `<p class="ai-empty" style="color:var(--accent-green);font-size:0.85rem;">✅ No exploitable attack paths identified.</p>`;
        } else {
            scenarios.forEach(sc => {
                const item = document.createElement("div");
                const sev = (sc.severity || "HIGH").toUpperCase();
                item.className = `ai-scenario-item sev-${sev}`;
                item.innerHTML = `
                    <div class="ai-scenario-header">
                        <span class="ai-scenario-title-text">${escapeHtml(sc.title || "Exploit Path")}</span>
                        <span class="sev-badge sev-${sev}">${sev}</span>
                    </div>
                    <p class="ai-scenario-narrative">${escapeHtml(sc.attack_vector || "")}</p>
                `;
                aiScenariosList.appendChild(item);
            });
        }
    }

    // Prioritized Checklist
    if (aiActionsList) {
        aiActionsList.innerHTML = "";
        const actions = data.prioritized_actions || [];
        if (actions.length === 0) {
            aiActionsList.innerHTML = `<p class="ai-empty" style="color:var(--text-secondary);font-size:0.85rem;">No immediate remediation actions required.</p>`;
        } else {
            actions.forEach((act, idx) => {
                const item = document.createElement("label");
                item.className = "ai-action-item";
                item.innerHTML = `
                    <input type="checkbox" id="ai-chk-${idx}">
                    <span>${escapeHtml(act)}</span>
                `;
                aiActionsList.appendChild(item);
            });
        }
    }

    // Unified Diff Patch
    currentDiff = data.unified_diff || "";
    if (aiDiffPre) {
        const codeEl = aiDiffPre.querySelector("code") || aiDiffPre;
        codeEl.innerHTML = formatDiffSyntax(currentDiff);
    }

    // Verification Commands
    currentVerifyCmds = data.verification_commands || [];
    if (aiVerifyList) {
        aiVerifyList.innerHTML = "";
        if (currentVerifyCmds.length === 0) {
            aiVerifyList.innerHTML = `<p class="ai-empty" style="color:var(--text-secondary);font-size:0.85rem;">No validation commands needed.</p>`;
        } else {
            currentVerifyCmds.forEach((cmd) => {
                const item = document.createElement("div");
                item.className = "ai-verify-item";
                item.innerHTML = `
                    <span class="ai-verify-cmd-text">${escapeHtml(cmd)}</span>
                    <button class="btn-copy" onclick="copySingleCommand(this, '${escapeHtml(cmd)}')">
                        <span class="copy-icon">📋</span>
                        <span class="copy-text">Copy</span>
                    </button>
                `;
                aiVerifyList.appendChild(item);
            });
        }
    }

    aiResults.classList.remove("hidden");
    aiResults.scrollIntoView({ behavior: "smooth", block: "start" });
}

function formatDiffSyntax(rawDiff) {
    if (!rawDiff || !rawDiff.trim()) {
        return `<span class="diff-ctx"># No code or manifest modifications required.</span>`;
    }
    const lines = rawDiff.split("\n");
    return lines.map(line => {
        const escaped = escapeHtml(line);
        if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff ")) {
            return `<span class="diff-meta">${escaped}</span>`;
        } else if (line.startsWith("@@")) {
            return `<span class="diff-hunk">${escaped}</span>`;
        } else if (line.startsWith("+")) {
            return `<span class="diff-add">${escaped}</span>`;
        } else if (line.startsWith("-")) {
            return `<span class="diff-del">${escaped}</span>`;
        } else {
            return `<span class="diff-ctx">${escaped}</span>`;
        }
    }).join("\n");
}

async function copyPatchDiff() {
    if (!currentDiff) return;
    try {
        await navigator.clipboard.writeText(currentDiff);
        const btn = document.getElementById("btn-copy-patch");
        if (btn) {
            btn.classList.add("copied");
            btn.querySelector(".copy-text").textContent = "✓ Copied!";
            setTimeout(() => {
                btn.classList.remove("copied");
                btn.querySelector(".copy-text").textContent = "Copy Patch";
            }, 2000);
        }
    } catch (e) {
        console.error("Clipboard copy failed", e);
    }
}

async function copyVerifyCommands() {
    if (!currentVerifyCmds || currentVerifyCmds.length === 0) return;
    try {
        await navigator.clipboard.writeText(currentVerifyCmds.join("\n"));
        const btn = document.getElementById("btn-copy-verify");
        if (btn) {
            btn.classList.add("copied");
            btn.querySelector(".copy-text").textContent = "✓ Copied!";
            setTimeout(() => {
                btn.classList.remove("copied");
                btn.querySelector(".copy-text").textContent = "Copy Commands";
            }, 2000);
        }
    } catch (e) {
        console.error("Clipboard copy failed", e);
    }
}

async function copySingleCommand(btnEl, cmd) {
    try {
        await navigator.clipboard.writeText(cmd);
        btnEl.classList.add("copied");
        btnEl.querySelector(".copy-text").textContent = "✓";
        setTimeout(() => {
            btnEl.classList.remove("copied");
            btnEl.querySelector(".copy-text").textContent = "Copy";
        }, 1500);
    } catch (e) {
        console.error("Clipboard copy failed", e);
    }
}

function animateCounter(el, target) {
    const duration = 1000;
    const start = performance.now();
    const startVal = 0;

    function update(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        const current = startVal + (target - startVal) * eased;
        el.textContent = current.toFixed(1);
        if (progress < 1) requestAnimationFrame(update);
    }

    requestAnimationFrame(update);
}

function escapeHtml(str) {
    if (str == null) return "";
    const div = document.createElement("div");
    div.textContent = String(str);
    return div.innerHTML;
}

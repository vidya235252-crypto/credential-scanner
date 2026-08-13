const repoInput = document.getElementById("repoInput");
const scanBtn = document.getElementById("scanBtn");
const refreshBtn = document.getElementById("refreshBtn");
const status = document.getElementById("status");
const loader = document.getElementById("loader");
const loaderText = document.getElementById("loaderText");
const filesScanned = document.getElementById("filesScanned");
const findingsCount = document.getElementById("findingsCount");
const skippedCount = document.getElementById("skippedCount");
const riskLevel = document.getElementById("riskLevel");
const secretDensity = document.getElementById("secretDensity");
const emptyState = document.getElementById("emptyState");
const resultsWrapper = document.getElementById("resultsWrapper");
const resultsCards = document.getElementById("resultsCards");
const historyBody = document.getElementById("historyBody");
const trendChartCanvas = document.getElementById("trendChart");
let trendChartInstance = null;
let remediationMap = null;

scanBtn.addEventListener("click", runScan);
refreshBtn.addEventListener("click", loadHistory);

repoInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
        runScan();
    }
});

const logoutBtn = document.getElementById("logoutBtn");
if (logoutBtn) {
    logoutBtn.addEventListener("click", function () {
        localStorage.removeItem("access_token");
        window.location.href = "/login";
    });
}

historyBody.addEventListener("click", function (e) {
    const button = e.target.closest(".deleteRowBtn");
    if (!button) {
        return;
    }
    deleteRepoHistory(button.dataset.owner, button.dataset.repo);
});

async function fetchConfidence(findings) {
    if (findings.length === 0) {
        return [];
    }
    try {
        const response = await fetch("/findings/confidence", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                findings: findings.map(f => ({
                    file: f.file,
                    type: f.type,
                    match: f.match,
                    method: f.method,
                    entropy: f.entropy ?? null
                }))
            })
        });
        if (!response.ok) {
            return [];
        }
        const data = await response.json();
        return data.results;
    } catch (err) {
        console.error(err);
        return [];
    }
}

function buildConfidenceCell(info) {
    if (!info) {
        return "-";
    }
    const level = info.confidence >= 70 ? "high" : info.confidence >= 40 ? "medium" : "low";
    const reasonsText = info.reasons.map(r => `${r.passed ? "\u2713" : "\u2717"} ${r.text}`).join("\n");
    return `<span class="confidence-badge confidence-${level}" title="${escapeHtml(reasonsText)}">${info.confidence}%</span>`;
}

async function loadRemediationMap() {
    if (remediationMap) {
        return remediationMap;
    }
    try {
        const response = await fetch("/remediation");
        remediationMap = await response.json();
    } catch (err) {
        console.error(err);
        remediationMap = { recommendations: {}, default: [] };
    }
    return remediationMap;
}

function buildRemediationCell(findingType) {
    if (!remediationMap) {
        return "-";
    }
    const steps = remediationMap.recommendations[findingType] || remediationMap.default;
    const tooltipText = steps.map((step, i) => `${i + 1}. ${step}`).join("\n");
    return `<span class="remediation-icon" title="${escapeHtml(tooltipText)}"><i class="fa-solid fa-screwdriver-wrench"></i></span>`;
}

function buildFindingCard(finding, confidenceInfo) {
    const severity = finding.method === "pattern" ? "HIGH" : "MEDIUM";
    const commitCell = finding.commit
        ? `${finding.commit.author} \u00b7 ${formatDate(finding.commit.date)}`
        : "Unknown";
    const confidenceCell = buildConfidenceCell(confidenceInfo);
    const remediationCell = buildRemediationCell(finding.type);
    const card = document.createElement("div");
    card.className = "finding-card";
    card.innerHTML = `
        <div class="finding-card-header">
            <span class="badge ${severity.toLowerCase()}">${severity}</span>
            <span class="finding-type">${finding.type}</span>
            ${confidenceCell}
        </div>
        <div class="finding-card-body">
            <p class="finding-file"><i class="fa-solid fa-file"></i> ${finding.file}</p>
            <code class="finding-value" title="${escapeHtml(finding.match)}">${escapeHtml(finding.match)}</code>
        </div>
        <div class="finding-card-footer">
            <span>${capitalize(finding.method)} detection</span>
            <span>${commitCell}</span>
            ${remediationCell}
        </div>
    `;
    return card;
}

function runScanWebSocket(owner, repo) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket("ws://localhost:8000/ws/scan");
        ws.onopen = function () {
        const token = localStorage.getItem("access_token");
        ws.send(JSON.stringify({ owner, repo, token }));
        };
        ws.onmessage = function (event) {
    const data = JSON.parse(event.data);
    if (data.status === "error") {
        ws.close();
        reject(new Error(data.message));
    } else if (data.status === "complete") {
        ws.close();
        resolve(data);
    } else if (data.status === "scanned" || data.status === "skipped_type" || data.status === "skipped_error") {
        loaderText.textContent = `Scanned ${data.file}...`;
    }
};
        ws.onerror = function (err) {
            reject(new Error("WebSocket connection failed"));
        };
    });
}

async function deleteRepoHistory(owner, repo) {
    const confirmed = confirm(`This will permanently delete scan history for ${owner}/${repo}. Are you sure?`);
    if (!confirmed) {
        return;
    }
    try {
        const response = await authFetch(`/scans/${owner}/${repo}`, { method: "DELETE" });
        if (!response.ok) {
            throw new Error("Failed to clear history");
        }
        loadHistory();
    } catch (err) {
        console.error(err);
        setStatus("Failed to clear history.", "#f85149");
    }
}

async function runScan() {
    const input = repoInput.value.trim();
    if (!input.includes("/")) {
        setStatus("Enter repository as owner/repository.", "#d29922");
        return;
    }
    const [owner, repo] = input.split("/");
    loader.classList.remove("hidden");
    scanBtn.disabled = true;
    setStatus("Scanning repository...", "#58a6ff");
    resultsCards.innerHTML = "";
    emptyState.classList.remove("hidden");
    resultsWrapper.classList.add("hidden");
    filesScanned.textContent = "-";
    findingsCount.textContent = "-";
    skippedCount.textContent = "-";
    riskLevel.textContent = "-";
    secretDensity.textContent = "-";
    try {
        const data = await runScanWebSocket(owner, repo);
        loader.classList.add("hidden");
        scanBtn.disabled = false;
        setStatus("Scan completed successfully.", "#3fb950");
        findingsCount.textContent = data.findings_count ?? data.findings.length;
        skippedCount.textContent = data.skipped_count ?? 0;
        if (data.files_scanned !== undefined)
            filesScanned.textContent = data.files_scanned;
        else
            filesScanned.textContent = "-";
        secretDensity.textContent = data.secret_density !== undefined
            ? data.secret_density + " / 100 files"
            : "-";
        const hygieneDiv = document.getElementById("hygieneChecks");
        hygieneDiv.innerHTML = `
            <p>${data.hygiene.has_gitignore ? "\u2705" : "\u274c"} .gitignore</p>
            <p>${data.hygiene.has_license ? "\u2705" : "\u274c"} License</p>
        `;
        if (data.findings.length === 0) {
            riskLevel.textContent = "SAFE";
            emptyState.classList.remove("hidden");
            emptyState.innerHTML = `
                <i class="fa-solid fa-circle-check"></i>
                <h3>No Secrets Found</h3>
                <p>The repository appears clean.</p>
            `;
            resultsWrapper.classList.add("hidden");
        } else {
            emptyState.classList.add("hidden");
            resultsWrapper.classList.remove("hidden");
            await loadRemediationMap();
            const confidenceResults = await fetchConfidence(data.findings);
            data.findings.forEach((finding, index) => {
                const card = buildFindingCard(finding, confidenceResults[index]);
                resultsCards.appendChild(card);
            });
            riskLevel.textContent = data.risk_score + "/100";
        }
        loadHistory();
        loadHistoryChart(owner, repo);
    } catch (err) {
        loader.classList.add("hidden");
        scanBtn.disabled = false;
        setStatus(err.message, "#f85149");
    }
}

async function loadHistoryChart(owner, repo) {
    try {
        const response = await authFetch(`/scans/history/${owner}/${repo}`);
        const data = await response.json();
        const validHistory = data.filter(entry => entry.risk_score !== null);
        const labels = validHistory.map(entry => formatDate(entry.scanned_at));
        const riskScores = validHistory.map(entry => entry.risk_score);
        if (trendChartInstance) {
            trendChartInstance.destroy();
        }
        trendChartInstance = new Chart(trendChartCanvas, {
            type: "line",
            data: {
                labels: labels,
                datasets: [{
                    label: "Risk Score",
                    data: riskScores,
                    borderColor: "#58a6ff",
                    backgroundColor: "rgba(88,166,255,.15)",
                    tension: 0.3,
                    fill: true
                }]
            },
            options: {
                scales: {
                    y: { min: 0, max: 100 }
                }
            }
        });
    } catch (err) {
        console.error(err);
    }
}

async function loadHistory() {
    try {
        const response = await authFetch("/scans");
        const scans = await response.json();
        historyBody.innerHTML = "";
        if (scans.length === 0) {
            historyBody.innerHTML = `
                <tr>
                    <td colspan="2" style="text-align:center;">No previous scans.</td>
                </tr>
            `;
            return;
        }
        scans.reverse().forEach(scan => {
            const row = document.createElement("tr");
            row.innerHTML = `
                
                <td>${scan.owner}/${scan.repo}</td>
                <td>${formatDate(scan.scanned_at)}</td>
                <td>
                    <button class="deleteRowBtn" data-owner="${scan.owner}" data-repo="${scan.repo}">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </td>
            `;
            historyBody.appendChild(row);
        });
    } catch (err) {
        console.error(err);
    }
}


function setStatus(message, color) {
    status.textContent = message;
    status.style.color = color;
}

function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}

function formatDate(dateString) {
    // SQLite's datetime('now') strings have no timezone marker, e.g. "2026-08-10 13:14:00".
    // GitHub API commit dates already come as full ISO 8601 strings with timezone info, e.g. "2026-08-09T12:00:00Z".
    // Only append "Z" when the string doesn't already carry timezone info, or it becomes unparseable ("...ZZ").
    const hasTimezone = /Z$|[+-]\d{2}:\d{2}$/.test(dateString);
    const isoString = hasTimezone ? dateString : dateString.replace(" ", "T") + "Z";
    const date = new Date(isoString);
    return date.toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });
}

loadHistory();

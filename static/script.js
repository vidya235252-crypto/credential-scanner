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
const resultsBody = document.getElementById("resultsBody");
const historyBody = document.getElementById("historyBody");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");
const trendChartCanvas = document.getElementById("trendChart");
let trendChartInstance = null;

scanBtn.addEventListener("click", runScan);
refreshBtn.addEventListener("click", loadHistory);
clearHistoryBtn.addEventListener("click", clearHistory);

repoInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
        runScan();
    }
});

historyBody.addEventListener("click", async function (e) {
    const button = e.target.closest(".deleteRowBtn");
    if (!button) {
        return;
    }
    const owner = button.dataset.owner;
    const repo = button.dataset.repo;
    const confirmed = confirm(`This will permanently delete scan history for ${owner}/${repo}. Are you sure?`);
    if (!confirmed) {
        return;
    }
    try {
        const response = await fetch(`/scans/${owner}/${repo}`, { method: "DELETE" });
        if (!response.ok) {
            throw new Error("Failed to clear history");
        }
        loadHistory();
    } catch (err) {
        console.error(err);
    }
});

function runScanWebSocket(owner, repo) {
    return new Promise((resolve, reject) => {
        const ws = new WebSocket("ws://localhost:8000/ws/scan");
        ws.onopen = function () {
            ws.send(JSON.stringify({ owner, repo }));
        };
        ws.onmessage = function (event) {
            const data = JSON.parse(event.data);
            if (data.status === "complete") {
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
    resultsBody.innerHTML = "";
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
            <p>${data.hygiene.has_gitignore ? "✅" : "❌"} .gitignore</p>
            <p>${data.hygiene.has_license ? "✅" : "❌"} License</p>
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
            let hasHigh = false;
            data.findings.forEach(finding => {
                const severity = finding.method === "pattern" ? "HIGH" : "MEDIUM";
                if (severity === "HIGH")
                    hasHigh = true;
                const row = document.createElement("tr");
                const commitCell = finding.commit
                    ? `${finding.commit.author} · ${formatDate(finding.commit.date)}`
                    : "Unknown";
                row.innerHTML = `
                    <td><span class="badge ${severity.toLowerCase()}">${severity}</span></td>
                    <td>${finding.type}</td>
                    <td>${finding.file}</td>
                    <td>${capitalize(finding.method)}</td>
                    <td><code>${escapeHtml(finding.match)}</code></td>
                    <td>${commitCell}</td>
                `;
                resultsBody.appendChild(row);
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
        const response = await fetch(`/scans/history/${owner}/${repo}`);
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
        const response = await fetch("/scans");
        const scans = await response.json();
        historyBody.innerHTML = "";
        if (scans.length === 0) {
            historyBody.innerHTML = `
                <tr>
                    <td colspan="3" style="text-align:center;">No previous scans.</td>
                </tr>
            `;
            return;
        }
        scans.reverse().forEach(scan => {
            const row = document.createElement("tr");
            row.innerHTML = `
                <td>#${scan.id}</td>
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

async function clearHistory() {
    const input = repoInput.value.trim();
    if (!input.includes("/")) {
        setStatus("Enter a repository (owner/repository) before clearing its history.", "#d29922");
        return;
    }
    const [owner, repo] = input.split("/");
    const confirmed = confirm(`This will permanently delete scan history for ${owner}/${repo}. Are you sure?`);
    if (!confirmed) {
        return;
    }
    try {
        const response = await fetch(`/scans/${owner}/${repo}`, { method: "DELETE" });
        if (!response.ok) {
            throw new Error("Failed to clear history");
        }
        loadHistory();
    } catch (err) {
        console.error(err);
        setStatus("Failed to clear history.", "#f85149");
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
    const date = new Date(dateString);
    return date.toLocaleString();
}

loadHistory();

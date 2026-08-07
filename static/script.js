const repoInput = document.getElementById("repoInput");
const scanBtn = document.getElementById("scanBtn");
const refreshBtn = document.getElementById("refreshBtn");

const status = document.getElementById("status");
const loader = document.getElementById("loader");

const filesScanned = document.getElementById("filesScanned");
const findingsCount = document.getElementById("findingsCount");
const skippedCount = document.getElementById("skippedCount");
const riskLevel = document.getElementById("riskLevel");

const emptyState = document.getElementById("emptyState");
const resultsWrapper = document.getElementById("resultsWrapper");
const resultsBody = document.getElementById("resultsBody");

const historyBody = document.getElementById("historyBody");

scanBtn.addEventListener("click", runScan);
refreshBtn.addEventListener("click", loadHistory);

repoInput.addEventListener("keypress", function (e) {
    if (e.key === "Enter") {
        runScan();
    }
});

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

    try {

        const response = await fetch("/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                owner,
                repo
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Scan failed");
        }

        loader.classList.add("hidden");

        scanBtn.disabled = false;

        setStatus("Scan completed successfully.", "#3fb950");

        findingsCount.textContent = data.findings_count ?? data.findings.length;
        skippedCount.textContent = data.skipped_count ?? 0;

        if (data.files_scanned !== undefined)
            filesScanned.textContent = data.files_scanned;
        else
            filesScanned.textContent = "-";

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

                const severity = finding.method === "pattern"
                    ? "HIGH"
                    : "MEDIUM";

                if (severity === "HIGH")
                    hasHigh = true;

                const row = document.createElement("tr");

                row.innerHTML = `
                    <td>
                        <span class="badge ${severity.toLowerCase()}">
                            ${severity}
                        </span>
                    </td>

                    <td>${finding.type}</td>

                    <td>${finding.file}</td>

                    <td>${capitalize(finding.method)}</td>

                    <td>
                        <code>${escapeHtml(finding.match)}</code>
                    </td>
                `;

                resultsBody.appendChild(row);

            });

            riskLevel.textContent = hasHigh ? "HIGH" : "MEDIUM";

        }

        loadHistory();

    } catch (err) {

        loader.classList.add("hidden");

        scanBtn.disabled = false;

        setStatus(err.message, "#f85149");

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
                    <td colspan="3" style="text-align:center;">
                        No previous scans.
                    </td>
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

    const date = new Date(dateString);

    return date.toLocaleString();

}

loadHistory();
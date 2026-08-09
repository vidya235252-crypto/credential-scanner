const repo1Input = document.getElementById("repo1Input");
const repo2Input = document.getElementById("repo2Input");
const compareBtn = document.getElementById("compareBtn");
const compareStatus = document.getElementById("compareStatus");
const compareResults = document.getElementById("compareResults");
const compareLoader = document.getElementById("compareLoader");
compareBtn.addEventListener("click", runCompare);
async function runCompare() {
    const input1 = repo1Input.value.trim();
    const input2 = repo2Input.value.trim();
    if (!input1.includes("/") || !input2.includes("/")) {
        setCompareStatus("Enter both repositories as owner/repository.", "#d29922");
        return;
    }
    const [owner1, repo1] = input1.split("/");
    const [owner2, repo2] = input2.split("/");
    compareBtn.disabled = true;
    compareLoader.classList.remove("hidden");
    setCompareStatus("", "");
    compareResults.classList.add("hidden");
    try {
        const response = await fetch("/compare", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ owner1, repo1, owner2, repo2 })
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || "Comparison failed");
        }
        compareBtn.disabled = false;
        compareLoader.classList.add("hidden");
        setCompareStatus("Comparison complete.", "#3fb950");
        renderComparison(data);
    } catch (err) {
        compareBtn.disabled = false;
        compareLoader.classList.add("hidden");
        setCompareStatus(err.message, "#f85149");
    }
}
function renderComparison(data) {
    const repo1 = data.repo1;
    const repo2 = data.repo2;
    const comparison = data.comparison;
    compareResults.innerHTML = `
        <div class="summary-grid">
            ${buildRepoCard(repo1)}
            ${buildRepoCard(repo2)}
        </div>
        <section class="panel">
            <h2><i class="fa-solid fa-code-compare"></i> Finding Differences</h2>
            <p><strong>${repo1.owner}/${repo1.repo}</strong> only:</p>
            ${buildTypeList(comparison.only_in_repo1)}
            <p><strong>${repo2.owner}/${repo2.repo}</strong> only:</p>
            ${buildTypeList(comparison.only_in_repo2)}
            <p>Shared finding types:</p>
            ${buildTypeList(comparison.shared_finding_types)}
        </section>
    `;
    compareResults.classList.remove("hidden");
}
function buildRepoCard(repo) {
    return `
        <div class="panel">
            <h3>${repo.owner}/${repo.repo}</h3>
            <p>Files Scanned: ${repo.files_scanned}</p>
            <p>Findings: ${repo.findings_count}</p>
            <p>Risk Score: ${repo.risk_score}/100</p>
            <p>Secret Density: ${repo.secret_density}</p>
            <p>${repo.hygiene.has_gitignore ? "✅" : "❌"} .gitignore</p>
            <p>${repo.hygiene.has_license ? "✅" : "❌"} License</p>
        </div>
    `;
}
function buildTypeList(types) {
    if (types.length === 0) {
        return "<p>None</p>";
    }
    return "<ul>" + types.map(t => `<li>${t}</li>`).join("") + "</ul>";
}
function setCompareStatus(message, color) {
    compareStatus.textContent = message;
    compareStatus.style.color = color;
}
import sys
import github_fetch
import patterns
import entropy
import report
import database
from concurrent.futures import ThreadPoolExecutor
import risk

SCANNABLE_EXTENSIONS = [
    ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml",
    ".env", ".txt", ".md", ".java", ".go", ".rb", ".php", ".sh",
    ".xml", ".ini", ".cfg", ".conf", ".properties", ".html", ".css"
]

IGNORED_FILENAMES = [
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "tsconfig.json",
    "tsconfig.app.json",
    "tsconfig.node.json"
]

def should_scan_file(path):
    for ignored in IGNORED_FILENAMES:
        if path.endswith(ignored):
            return False
    
    for ext in SCANNABLE_EXTENSIONS:
        if path.endswith(ext):
            return True
    
    return False


def scan_one_file(file):
    path = file["path"]
    url = file["url"]
    
    if not should_scan_file(path):
        return None
    
    try:
        content = github_fetch.get_file_content(url)
    except Exception:
        return {"skipped": path}
    
    file_findings = []
    
    pattern_matches = patterns.scan_text(content)
    for match in pattern_matches:
        file_findings.append({
            "file": path,
            "type": match["type"],
            "match": match["match"],
            "method": "pattern"
        })
    
    entropy_matches = entropy.scan_text(content)
    for match in entropy_matches:
        file_findings.append({
            "file": path,
            "type": "High entropy string",
            "match": match["string"],
            "entropy": match["entropy"],
            "method": "entropy"
        })
    
    return {"findings": file_findings}

def scan_repo(owner, repo):
    repo_info = github_fetch.get_repo_info(owner, repo)
    branch = repo_info["default_branch"]

    hygiene = github_fetch.check_hygiene(owner, repo)
    
    files = github_fetch.get_file_list(owner, repo, branch)
    
    findings = []
    skipped_files = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(scan_one_file, files)
    
    for result in results:
        if result is None:
            continue
        if "skipped" in result:
            skipped_files.append(result["skipped"])
        else:
            findings.extend(result["findings"])
    
    risk_score = risk.calculate_risk_score(findings)

    density = round((len(findings) / len(files)) * 100, 2) if len(files) > 0 else 0
    
    return findings, skipped_files, len(files), risk_score, hygiene, density

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py owner/repo")
        sys.exit(1)
    
    remaining, limit = github_fetch.check_rate_limit()
    print(f"GitHub API requests remaining: {remaining}/{limit}")
    
    if remaining < 50:
        print("WARNING: Low on API requests. This scan may fail partway through.")
    
    repo_input = sys.argv[1]
    owner, repo = repo_input.split("/")
    
    print(f"Scanning {owner}/{repo}...")
    results, skipped, files_scanned, risk_score, hygiene, density = scan_repo(owner, repo)
    
    if skipped:
        print(f"\nSkipped {len(skipped)} file(s) that couldn't be read:")
        for path in skipped:
            print(f"  - {path}")
    
    report.print_report(results)
    report.save_report(results)
    
    database.init_db()
    scan_id = database.save_scan(owner, repo, results, len(skipped), risk_score)
    print(f"Scan saved to database with id {scan_id}")



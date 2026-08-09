import sys
import github_fetch
import patterns
import entropy
import report
import database
from concurrent.futures import ThreadPoolExecutor
import risk
from functools import partial

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


def scan_one_file(file, owner, repo):
    path = file["path"]
    url = file["url"]
    
    if not should_scan_file(path):
        return None
    
    try:
        content = github_fetch.get_file_content(url)
    except Exception:
        return {"skipped": path}
    
    file_findings = []

    commit_info = None
    
    pattern_matches = patterns.scan_text(content)
    entropy_matches = entropy.scan_text(content)
    
    if pattern_matches or entropy_matches:
        commit_info = github_fetch.get_introducing_commit(owner, repo, path)
    
    for match in pattern_matches:
        file_findings.append({
            "file": path,
            "type": match["type"],
            "match": match["match"],
            "method": "pattern",
            "commit": commit_info
        })
    
    for match in entropy_matches:
        file_findings.append({
            "file": path,
            "type": "High entropy string",
            "match": match["string"],
            "entropy": match["entropy"],
            "method": "entropy",
            "commit": commit_info
        })
    
    return {"findings": file_findings}

def scan_repo(owner, repo):
    repo_info = github_fetch.get_repo_info(owner, repo)
    branch = repo_info["default_branch"]

    files = github_fetch.get_file_list(owner, repo, branch)

    file_paths = [f["path"] for f in files]
    hygiene = github_fetch.check_hygiene(file_paths)
    
    findings = []
    skipped_files = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        scan_with_context = partial(scan_one_file, owner=owner, repo=repo)
        results = executor.map(scan_with_context, files)
    
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

def compare_repos(owner1, repo1, owner2, repo2):
    with ThreadPoolExecutor(max_workers=2) as executor:
        future1 = executor.submit(scan_repo, owner1, repo1)
        future2 = executor.submit(scan_repo, owner2, repo2)
        
        findings1, skipped1, files1, risk1, hygiene1, density1 = future1.result()
        findings2, skipped2, files2, risk2, hygiene2, density2 = future2.result()
    
    return {
        "repo1": {
            "owner": owner1,
            "repo": repo1,
            "findings_count": len(findings1),
            "risk_score": risk1,
            "secret_density": density1,
            "files_scanned": files1,
            "hygiene": hygiene1,
            "findings": findings1
        },
        "repo2": {
            "owner": owner2,
            "repo": repo2,
            "findings_count": len(findings2),
            "risk_score": risk2,
            "secret_density": density2,
            "files_scanned": files2,
            "hygiene": hygiene2,
            "findings": findings2
        }
    }

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



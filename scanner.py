import sys
import github_fetch
import patterns
import entropy
import report

def scan_repo(owner, repo):
    findings = []
    skipped_files = []

    repo_info = github_fetch.get_repo_info(owner, repo)
    branch = repo_info["default_branch"]
    
    files = github_fetch.get_file_list(owner, repo, branch)
    
    for file in files:
        path = file["path"]
        url = file["url"]
        
        try:
            content = github_fetch.get_file_content(url)
        except Exception:
            skipped_files.append(path)
            continue
        
        pattern_matches = patterns.scan_text(content)
        for match in pattern_matches:
            findings.append({
                "file": path,
                "type": match["type"],
                "match": match["match"],
                "method": "pattern"
            })
        
        entropy_matches = entropy.scan_text(content)
        for match in entropy_matches:
            findings.append({
                "file": path,
                "type": "High entropy string",
                "match": match["string"],
                "entropy": match["entropy"],
                "method": "entropy"
            })
    
    return findings, skipped_files

if __name__ == "__main__":
    remaining, limit = github_fetch.check_rate_limit()
    print(f"GitHub API requests remaining: {remaining}/{limit}")
    
    if remaining < 50:
        print("WARNING: Low on API requests. This scan may fail partway through.")
    if len(sys.argv) != 2:
        print("Usage: python scanner.py owner/repo")
        sys.exit(1)
    
    repo_input = sys.argv[1]
    owner, repo = repo_input.split("/")
    
    print(f"Scanning {owner}/{repo}...")
    results, skipped = scan_repo(owner, repo)
    
    if skipped:
        print(f"\nSkipped {len(skipped)} file(s) that couldn't be read:")
        for path in skipped:
            print(f"  - {path}")
    
    report.print_report(results)
    report.save_report(results)

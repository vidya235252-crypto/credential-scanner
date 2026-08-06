import json

def save_report(findings, filename="report.json"):
    with open(filename, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"Report saved to {filename}")

import json

def get_severity(finding):
    if finding["method"] == "pattern":
        return "HIGH"
    else:
        return "MEDIUM"

def print_report(findings):
    if len(findings) == 0:
        print("No potential secrets found.")
        return
    
    print(f"\nFound {len(findings)} potential secret(s):\n")
    
    for finding in findings:
        severity = get_severity(finding)
        print(f"[{severity}] {finding['file']} — {finding['type']}")
        print(f"    Match: {finding['match']}")
        print()

def save_report(findings, filename="report.json"):
    with open(filename, "w") as f:
        json.dump(findings, f, indent=2)
    print(f"Report saved to {filename}")
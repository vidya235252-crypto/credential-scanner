import re

PATTERNS = {
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
    "Generic API Key": r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9]{20,40}['\"]",
    "Private Key Header": r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z-]{10,48}"
}

def scan_text(text):
    findings = []
    for name, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            findings.append({"type": name, "match": match})
    return findings

if __name__ == "__main__":
    fake_text = """
    AWS_KEY = AKIAIOSFODNN7EXAMPLE
    aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    api_key = "sk1234567890abcdef1234567890"
    -----BEGIN RSA PRIVATE KEY-----
    slack_token = xoxb-FAKE0000000-notarealtoken000
    normal_variable = "hello world"
    """
    
    results = scan_text(fake_text)
    for r in results:
        print(r["type"], "->", r["match"])
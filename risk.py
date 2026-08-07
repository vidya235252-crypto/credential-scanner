RISK_WEIGHTS = {
    "AWS Access Key ID": 40,
    "AWS Secret Key": 40,
    "Private Key Header": 40,
    "Slack Token": 25,
    "Generic API Key": 20,
    "High entropy string": 10
}

def calculate_risk_score(findings):
    score = 0
    for finding in findings:
        weight = RISK_WEIGHTS.get(finding["type"], 10)
        score += weight
    
    return min(score, 100)
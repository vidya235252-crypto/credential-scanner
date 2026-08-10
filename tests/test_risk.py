from risk import calculate_risk_score

def test_calculate_risk_score_sums_weights_correctly():
    findings = [
        {"type": "Slack Token"},
        {"type": "Generic API Key"}
    ]
    score = calculate_risk_score(findings)
    assert score == 45

def test_calculate_risk_score_caps_at_100():
    findings = [
        {"type": "AWS Access Key ID"},
        {"type": "AWS Secret Key"},
        {"type": "Private Key Header"}
    ]
    score = calculate_risk_score(findings)
    assert score == 100

def test_calculate_risk_score_empty_findings_is_zero():
    score = calculate_risk_score([])
    assert score == 0

def test_calculate_risk_score_unknown_type_uses_default_weight():
    findings = [{"type": "Some Brand New Finding Type"}]
    score = calculate_risk_score(findings)
    assert score == 10
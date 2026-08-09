from patterns import scan_text

def test_scan_text_detects_aws_access_key():
    text = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    results = scan_text(text)
    assert len(results) == 1
    assert results[0]["type"] == "AWS Access Key ID"
    assert results[0]["match"] == "AKIAIOSFODNN7EXAMPLE"

def test_scan_text_ignores_lowercase_akia():
    text = 'aws_key = "akiaiosfodnn7example"'
    results = scan_text(text)
    assert len(results) == 0

def test_scan_text_detects_slack_token():
    text = 'slack_token = "xoxb-FAKE0000000-notarealtoken000"'
    results = scan_text(text)
    slack_findings = [r for r in results if r["type"] == "Slack Token"]
    assert len(slack_findings) == 1

def test_scan_text_detects_private_key_header():
    text = "-----BEGIN RSA PRIVATE KEY-----"
    results = scan_text(text)
    assert len(results) == 1
    assert results[0]["type"] == "Private Key Header"
    assert results[0]["match"] == "-----BEGIN RSA PRIVATE KEY-----"

def test_scan_text_returns_empty_for_clean_text():
    text = "This is just a normal sentence with no secrets in it."
    results = scan_text(text)
    assert results == []

def test_scan_text_detects_multiple_findings_in_one_string():
    text = '''
    AWS_KEY = AKIAIOSFODNN7EXAMPLE
    slack_token = xoxb-FAKE0000000-notarealtoken000
    '''
    results = scan_text(text)
    assert len(results) == 2
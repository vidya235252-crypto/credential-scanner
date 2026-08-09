from patterns import scan_text

def test_scan_text_detects_aws_access_key():
    text = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    results = scan_text(text)
    assert len(results) == 1
    assert results[0]["type"] == "AWS Access Key ID"
    assert results[0]["match"] == "AKIAIOSFODNN7EXAMPLE"
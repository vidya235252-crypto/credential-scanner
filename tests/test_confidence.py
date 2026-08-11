import confidence


def test_real_looking_secret_scores_high():
    finding = {"type": "AWS Access Key ID", "match": "AKIA3F9QK7ZXMLD82VNB", "method": "pattern"}
    result = confidence.calculate_confidence(finding, "config.py")
    assert result["confidence"] == 100


def test_placeholder_in_test_file_scores_zero():
    finding = {"type": "Generic API Key", "match": "example_api_key_123", "method": "pattern"}
    result = confidence.calculate_confidence(finding, "tests/fixtures/config.py")
    assert result["confidence"] == 0


def test_real_looking_secret_in_test_file_is_lowered_not_suppressed():
    finding = {"type": "AWS Access Key ID", "match": "AKIA3F9QK7ZXMLD82VNB", "method": "pattern"}
    result = confidence.calculate_confidence(finding, "tests/fixtures/config.py")
    # test-file location should reduce confidence, but not zero it out
    # the way a placeholder match does
    assert 0 < result["confidence"] < 100


def test_entropy_only_method_scores_lower_than_pattern_match():
    pattern_finding = {"type": "AWS Access Key ID", "match": "AKIA3F9QK7ZXMLD82VNB", "method": "pattern"}
    entropy_finding = {"type": "High entropy string", "match": "AKIA3F9QK7ZXMLD82VNB", "method": "entropy", "entropy": 4.12}
    pattern_result = confidence.calculate_confidence(pattern_finding, "config.py")
    entropy_result = confidence.calculate_confidence(entropy_finding, "config.py")
    assert entropy_result["confidence"] < pattern_result["confidence"]


def test_is_placeholder_detects_known_keywords():
    assert confidence.is_placeholder("example_api_key_123") is True
    assert confidence.is_placeholder("AKIA3F9QK7ZXMLD82VNB") is False


def test_is_test_file_detects_common_markers():
    assert confidence.is_test_file("tests/fixtures/config.py") is True
    assert confidence.is_test_file("src/config.py") is False


def test_score_never_exceeds_bounds():
    # even a finding that fails every signal should clamp at 0, not go negative
    finding = {"type": "Generic API Key", "match": "test_dummy_placeholder", "method": "entropy", "entropy": 1.0}
    result = confidence.calculate_confidence(finding, "tests/fixtures/mock.py")
    assert 0 <= result["confidence"] <= 100

import entropy

PLACEHOLDER_KEYWORDS = [
    "example", "test", "fake", "dummy", "sample", "placeholder",
    "changeme", "your_key", "xxxx", "000000"
]

TEST_PATH_MARKERS = ["test", "tests/", "spec", "example", "examples/", "mock", "fixture", "demo"]

ENTROPY_THRESHOLD = 4.0


def is_placeholder(value):
    lowered = value.lower()
    return any(keyword in lowered for keyword in PLACEHOLDER_KEYWORDS)


def is_test_file(path):
    lowered = path.lower()
    return any(marker in lowered for marker in TEST_PATH_MARKERS)


def calculate_confidence(finding, file_path):
    reasons = []
    score = 50  # baseline

    if finding["method"] == "pattern":
        score += 25
        reasons.append({"passed": True, "text": "Matches known credential format"})
    else:
        reasons.append({"passed": False, "text": "No known credential format matched (entropy-based only)"})

    match_entropy = finding.get("entropy")
    if match_entropy is None:
        match_entropy = entropy.calculate_entropy(finding["match"])

    if match_entropy >= ENTROPY_THRESHOLD:
        score += 15
        reasons.append({"passed": True, "text": f"High entropy value ({round(match_entropy, 2)})"})
    else:
        score -= 15
        reasons.append({"passed": False, "text": f"Low entropy value ({round(match_entropy, 2)})"})

    if is_test_file(file_path):
        score -= 30
        reasons.append({"passed": False, "text": "Located in a test/example file"})
    else:
        score += 10
        reasons.append({"passed": True, "text": "Not located in a test/example file"})

    if is_placeholder(finding["match"]):
        score -= 40
        reasons.append({"passed": False, "text": "Matches a known placeholder pattern"})
    else:
        score += 10
        reasons.append({"passed": True, "text": "Not a known placeholder value"})

    score = max(0, min(score, 100))

    return {"confidence": score, "reasons": reasons}


if __name__ == "__main__":
    real_looking = {"type": "AWS Access Key ID", "match": "AKIA3F9QK7ZXMLD82VNB", "method": "pattern"}
    print(calculate_confidence(real_looking, "config.py"))

    fake_looking = {"type": "Generic API Key", "match": "example_api_key_123", "method": "pattern"}
    print(calculate_confidence(fake_looking, "tests/fixtures/config.py"))

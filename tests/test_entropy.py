from entropy import calculate_entropy, scan_text

def test_calculate_entropy_zero_for_repeated_character():
    assert calculate_entropy("aaaaaaaa") == 0

def test_calculate_entropy_higher_for_more_varied_string():
    low_entropy = calculate_entropy("aaaaaaaa")
    high_entropy = calculate_entropy("kX9mQ2zP")
    assert high_entropy > low_entropy

def test_calculate_entropy_empty_string_is_zero():
    assert calculate_entropy("") == 0
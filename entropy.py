import math
import re
from collections import Counter

def calculate_entropy(text):
    if len(text) == 0:
        return 0
    
    counts = Counter(text)
    length = len(text)
    entropy = 0
    
    for count in counts.values():
        probability = count / length
        entropy += -probability * math.log2(probability)
    
    return entropy

def find_candidate_strings(text):
    return re.findall(r"['\"]([A-Za-z0-9+/=_-]{8,})['\"]", text)

def scan_text(text, threshold=4.0):
    findings = []
    candidates = find_candidate_strings(text)
    
    for candidate in candidates:
        score = calculate_entropy(candidate)
        if score >= threshold:
            findings.append({"string": candidate, "entropy": round(score, 2)})
    
    return findings

if __name__ == "__main__":
    normal_string = "hello world this is normal text"
    random_string = "kX9#mQ2zP7vL4wR8"
    
    print("Normal string entropy:", calculate_entropy(normal_string))
    print("Random string entropy:", calculate_entropy(random_string))
    
    fake_text = '''
    greeting = "hello world"
    secret_token = "kX9mQ2zP7vL4wR8nJ3fT6"
    normal_var = "test"
    '''
    
    results = scan_text(fake_text)
    for r in results:
        print(r["string"], "->", r["entropy"])
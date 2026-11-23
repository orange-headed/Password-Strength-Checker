import math
import string
import re

COMMON_PASSWORDS={
   "admin",
   "password",
   "abcdefg",
   "abc1234",
   "letmein",
   "welcome",
   "qwerty",
   "wasd",
   "asdfgh",
   "123456789",
}

def cal_entropy(password: str) -> float:
    if not password:
        return 0.0

    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += 32

    return round(len(password)*math.log2(pool_size),2)

def detect_weak_patterns(password):
    issues = []
    p = password.lower()

    if re.search(r"(.)\1{2,}", p):
        issues.append("Contains repeated characters")

    sequences = [
        "0123456789",
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm"
    ]

    for sequence in sequences:
        for i in range(len(sequence) - 2):
            if sequence[i:i+3] in p:
                issues.append("Contains a predictable sequence")
                break

    return issues

def get_suggestions(password, issues):
    suggestions = []

    if len(password) < 12:
        suggestions.append("Use at least 12 characters")

    if not any(c.isupper() for c in password):
        suggestions.append("Consider adding uppercase letters")

    if not any(c.islower() for c in password):
        suggestions.append("Consider adding lowercase letters")

    if not any(c.isdigit() for c in password):
        suggestions.append("Consider adding numbers")

    if not any(c in string.punctuation for c in password):
        suggestions.append("Consider adding special characters")

    if issues:
        suggestions.append("Avoid repeated or predictable patterns")

    return suggestions

def get_verdict(score: int) -> str:
    if score < 40:
        return "Weak"
    elif score <60:
        return "Moderate"
    elif score <80:
        return "Strong"
    else:
        return "Very strong"

def score_password(password):
    length = len(password)
    entropy = cal_entropy(password)

    if password.lower() in COMMON_PASSWORDS:
        return {
            "length": length,
            "entropy": entropy,
            "score": 0,
            "verdict": "Weak",
            "issues": ["Common password"]
        }

    score = 0

    # Character variety
    if any(c.islower() for c in password):
        score += 10

    if any(c.isupper() for c in password):
        score += 10

    if any(c.isdigit() for c in password):
        score += 10

    if any(c in string.punctuation for c in password):
        score += 10

    # Length contribution
    score += min(length * 2, 40)

    # Entropy contribution
    score += min(int(entropy * 0.3), 30)

    # Detect predictable patterns
    issues = detect_weak_patterns(password)

    if issues:
        score -= 15 * len(issues)

    score = max(0, min(100, score))

    return {
        "length": length,
        "entropy": entropy,
        "score": score,
        "verdict": get_verdict(score),
        "issues": issues
    }

def main():
    print("=== Python Password Strength Checker ===")

    password = input("Enter a password to check: ")

    result = score_password(password)

    suggestions = get_suggestions(password, result["issues"])

    print("\n--- Password Analysis ---")
    print(f"Length      : {result['length']}")
    print(f"Entropy     : {result['entropy']}")
    print(f"Score       : {result['score']}/100")
    print(f"Verdict     : {result['verdict']}")
    print(f"Issues      : {result['issues']}")
    print(f"Suggestions : {suggestions}")


if __name__ == "__main__":
    main()





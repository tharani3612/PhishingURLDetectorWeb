# phishing_detector.py
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "bank", "secure", "account",
    "confirm", "signin", "password", "ebayisapi", "webscr"
]

def score_url(url: str):
    """Analyze a URL and return (score, reasons, features)."""
    score = 0
    reasons = []

    parsed = urlparse(url)
    features = {}

    # HTTPS check
    features["uses_https"] = parsed.scheme == "https"
    if not features["uses_https"]:
        score += 1
        reasons.append("Not using HTTPS")

    # IP address check
    features["has_ip"] = bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", parsed.hostname or ""))
    if features["has_ip"]:
        score += 3
        reasons.append("Uses IP address instead of domain")

    # '@' check
    features["has_at"] = "@" in url
    if features["has_at"]:
        score += 1
        reasons.append("Contains '@' symbol")

    # '-' check
    features["has_dash"] = "-" in parsed.netloc
    if features["has_dash"]:
        score += 1
        reasons.append("Domain contains '-'")

    # dot count
    features["num_dots"] = url.count(".")
    if features["num_dots"] > 5:
        score += 1
        reasons.append("Too many dots in URL")

    # length
    features["length"] = len(url)
    if features["length"] > 75:
        score += 1
        reasons.append("URL too long")

    # query parameters
    features["num_query_params"] = url.count("=")
    if features["num_query_params"] > 2:
        score += 1
        reasons.append("Too many query parameters")

    # double slash redirect
    features["has_redirect_double_slash"] = "//" in url[8:]
    if features["has_redirect_double_slash"]:
        score += 1
        reasons.append("Contains '//' redirect pattern")

    # suspicious words
    features["suspicious_words"] = [w for w in SUSPICIOUS_WORDS if w in url.lower()]
    features["suspicious_words_count"] = len(features["suspicious_words"])
    if features["suspicious_words_count"] > 0:
        score += features["suspicious_words_count"]
        reasons.append(f"Suspicious words present: {features['suspicious_words']}")

    # long substring
    features["contains_long_substring"] = any(len(part) > 30 for part in parsed.netloc.split("."))
    if features["contains_long_substring"]:
        score += 1
        reasons.append("Contains unusually long domain substring")

    return score, reasons, features

def classify(score: int) -> str:
    """Label a URL based on score."""
    if score <= 2:
        return "safe"
    elif score <= 5:
        return "suspicious"
    else:
        return "phishing"

# Allow command-line testing too
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        test_url = sys.argv[1]
        s, r, f = score_url(test_url)
        print(f"\nURL: {test_url}\nScore: {s} => {classify(s)}\n")
        print("Reasons:")
        for reason in r:
            print(" -", reason)
    else:
        print("Usage: python phishing_detector.py <url>")



import requests
import socket
import ssl
import whois
from datetime import datetime
import pandas as pd
import re
import numpy as np
from urllib.parse import urlparse
from difflib import SequenceMatcher
import math
from collections import Counter
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle
API_KEY = "YOUR_ACTUAL_API_KEY"


with open("tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

def google_safe_check(url):
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    body = {
        "client": {"clientId": "project", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        res = requests.post(endpoint, json=body)
        return 1 if res.status_code == 200 and res.json() else 0
    except:
        return 0


def domain_age(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        return (datetime.now() - creation).days
    except:
        return -1


def has_dns(domain):
    try:
        socket.gethostbyname(domain)
        return 1
    except:
        return 0


def has_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
        return 1
    except:
        return 0


import re
import numpy as np
from urllib.parse import urlparse

# -------------------------
# Constants
# -------------------------
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "secure", "verify", "verification",
    "account", "update", "confirm", "password",
    "authentication", "session", "validate", "validation",
    "auth", "access", "security", "alert", "bank", "payment"
]

TRUSTED_DOMAINS = [
    "google.com", "github.com", "microsoft.com",
    "amazon.in", "irctc.co.in", "wikipedia.org",
    "python.org", "stackoverflow.com","amazon.com"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"
]

TRUSTED_BRANDS = [
    "google", "amazon", "paypal", "microsoft", "bank", "apple"
]

LEGIT_WORDS = ["wiki", "docs", "api", "github", "stackoverflow"]


# -------------------------
# Helper Functions
# -------------------------
def shannon_entropy(string):
    probs = [float(string.count(c)) / len(string) for c in set(string)]
    return -sum(p * np.log2(p) for p in probs)


def domain_entropy(domain):
    if len(domain) == 0:
        return 0
    probs = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * np.log2(p) for p in probs)


def brand_mismatch(domain):
    for brand in TRUSTED_BRANDS:
        if brand in domain:
            if domain.endswith(brand + ".com") or domain.endswith(brand + ".in"):
                return 0
            return 1
    return 0


def detect_fake_brand(url,domain):
    suspicious_patterns = [
        ("google", ["g00gle", "goog1e"]),
        ("facebook", ["faceb00k"]),
        ("amazon", ["amaz0n"]),
        ("paypal", ["paypa1"]),
    ]

    for brand, variants in suspicious_patterns:
        for v in variants:
            if v in domain:
                return 1
    return 0


def detect_repeated_chars(domain):
    domain = domain.replace(".", "")
    return 1 if re.search(r'(.)\1{3,}', domain) else 0


# -------------------------
# Feature Extraction
# -------------------------
def extract_features(url):
    features = {}

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    # -------------------------
    # Domain randomness
    # -------------------------

    def entropy(s):
      prob = [n_x / len(s) for x, n_x in Counter(s).items()]
      return -sum(p * math.log2(p) for p in prob)

    features['domain_random'] = 1 if entropy(domain) > 4.2 else 0

    # -------------------------
    # Basic lexical features
    # -------------------------
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)

    features['num_dots'] = url.count('.')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['digit_ratio'] = features['num_digits'] / len(url)

    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['many_hyphens'] = 1 if features['num_hyphens'] >= 2 else 0

    # -------------------------
    # Protocol features
    # -------------------------
    features['has_https'] = 1 if url.startswith('https') else 0
    features['has_http'] = 1 if url.startswith('http://') else 0

    # -------------------------
    # Domain structure
    # -------------------------
    features['num_subdomains'] = domain.count('.')
    features['has_ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0

    # -------------------------
    # Suspicious symbols
    # -------------------------
    features['has_at'] = 1 if '@' in url else 0
    features['has_double_slash'] = 1 if '//' in url[8:] else 0

    # -------------------------
    # Keyword features
    # -------------------------
    features['num_keywords'] = sum(1 for word in SUSPICIOUS_KEYWORDS if word in url)

    # -------------------------
    # Shortener detection
    # -------------------------
    features['is_shortened'] = 1 if any(s in domain for s in SHORTENERS) else 0
    
    # -------------------------
    # Entropy (full URL)
    # -------------------------
    entropy = shannon_entropy(url)
    features['entropy'] = entropy
    features['entropy_flag'] = 1 if (entropy > 4.5 and features['num_digits'] > 2) else 0

    # -------------------------
    # Path features
    # -------------------------
    features['has_login_path'] = 1 if "login" in path else 0
    features['path_depth'] = path.count('/')

    # -------------------------
    # Advanced features
    # -------------------------
    features['brand_mismatch'] = brand_mismatch(domain)
    features['legit_path'] = 1 if any(w in url for w in LEGIT_WORDS) else 0
    features['fake_brand'] = detect_fake_brand(url,domain)
    #repeated characters
    features['repeated_chars'] = detect_repeated_chars(domain)

    features['http_login'] = 1 if url.startswith("http://") and "login" in url else 0

    return features



def heuristic_checks(url, domain, features):
    h_score = 0
    reasons = []

    # 🔸 HTTP login (important)
    if features.get('http_login', 0):
        h_score += 0.3
        reasons.append("Login page over HTTP")

    # 🔸 Suspicious symbol
    if "@" in url:
        h_score += 0.2
        reasons.append("Contains @ symbol")

    # 🔸 Too many hyphens
    if domain.count('-') >= 2:
        h_score += 0.2
        reasons.append("Too many hyphens in domain")

    # 🔸 IP address usage
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        h_score += 0.3
        reasons.append("Uses IP address instead of domain")

    # 🔸 Keyword penalty (only if NOT trusted)
    if not any(domain.endswith(d) for d in TRUSTED_DOMAINS):
        if features.get('num_keywords', 0) > 2:
            h_score += 0.2
            reasons.append("Too many suspicious keywords")

    return h_score, reasons


def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()  
def has_repeated_chars(domain):
    return 1 if re.search(r'(.)\1{2,}', domain) else 0    




KNOWN_BRANDS = ["google", "facebook", "amazon", "paypal", "microsoft", "apple"]

def detect_fake_brand(url, domain):
    url = url.lower()
    domain = domain.lower()

    brands = ["google", "facebook", "amazon", "paypal", "apple", "microsoft"]

    for brand in brands:
        if brand in url and not domain.endswith(brand + ".com"):
            return 1

    return 0



def detect_repeated_chars(domain):
    # Remove dots (so subdomains don't interfere)
    domain = domain.replace(".", "")
    
    # Only flag if 4+ repeated characters
    return 1 if re.search(r'(.)\1{3,}', domain) else 0


def has_ip(url):
    return 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0    

def normalize_text(s):
    return s.lower().replace("0", "o").replace("1", "l").replace("3", "e")


def strong_phishing_check(url, domain):
    norm_domain = normalize_text(domain)
    original_domain = domain.lower()

    brands = ["google", "facebook", "amazon", "paypal", "apple", "microsoft"]

    for brand in brands:
        # Extract main domain (remove www and TLD)
        core = original_domain.replace("www.", "").split(".")[0]
        norm_core = normalize_text(core)

        # 🔥 1. Exact impersonation (after normalization)
        if brand in norm_core and not original_domain.endswith(brand + ".com"):
            return True, f"Impersonates {brand}"

        # 🔥 2. Fuzzy match (typo attack)
        if is_similar(norm_core, brand) and norm_core != brand:
            return True, f"Looks similar to {brand} (possible typo attack)"

    return False, ""

def model_predict(url, model):
    feats = extract_features(url)
    X = pd.DataFrame([feats])
    prob = model.predict_proba(X)[0][1]
    return prob, feats

def reputation_check(domain):
    for d in TRUSTED_DOMAINS:
        if domain == d or domain.endswith("." + d):
            return "trusted"
    return "unknown"



def is_similar(a, b, threshold=0.8):
    return SequenceMatcher(None, a, b).ratio() > threshold


def brand_mismatch(domain):
    legit_domains = [
        "microsoftonline.com",
        "google.com",
        "amazon.com",
        "github.com"
    ]

    for legit in legit_domains:
        if legit in domain:
            return 0

    for brand in TRUSTED_BRANDS:
        if brand in domain:
            if not domain.endswith(brand + ".com") and not domain.endswith(brand + ".in"):
                return 1

    return 0


def predict_url(url, model):
    # extract features
    features = extract_features(url)
    
    # convert to dataframe
    import pandas as pd
    X = pd.DataFrame([features])
    
    # predict probability
    prob = model.predict_proba(X)[0][1]  # phishing probability
    
    # prediction
    label = "Phishing" if prob > 0.5 else "Legitimate"
    
    return label, prob, features


def normalize_url(url):
    url = url.strip().lower()
    
    # remove spaces
    url = url.replace(" ", "")
    
    # add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        
    return url


def explain_prediction(features):
    reasons = []

    if features.get('domain_random', 0) == 1:
        reasons.append("Random-looking domain")

    if features.get('entropy', 0) > 4:
        reasons.append("High randomness in URL")

    if features.get('num_digits', 0) > 5:
        reasons.append("Contains many digits")

    if features.get('num_keywords', 0) > 0:
        reasons.append("Contains phishing-related keywords")

    if features.get('has_ip', 0) == 1:
        reasons.append("Uses IP address instead of domain")

    if features.get('is_shortened', 0) == 1:
        reasons.append("Uses URL shortener")

    if features.get('num_subdomains', 0) > 3:
        reasons.append("Too many subdomains")

    if features.get('has_at', 0) == 1:
        reasons.append("Contains '@' symbol")

    if features.get('brand_mismatch', 0) == 1:
        reasons.append("Brand impersonation pattern")

    if features.get('fake_brand', 0) == 1:
        reasons.append("Fake brand spelling detected")

    if not reasons:
        reasons.append("Looks normal")

    return reasons

def final_decision(url,model,dl_model):
    url = normalize_url(url)

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # =========================
    # 🚨 STRONG BRAND CHECK (TOP PRIORITY)
    # =========================
    is_phish, reason = strong_phishing_check(url, domain)
    if is_phish:
        return "Phishing", 0.95, [
            "Strong brand impersonation detected",
            reason
        ]

    # =========================
    # 🤖 MODEL + HEURISTICS
    # =========================
    prob, features = model_predict(url,model)
    dl_prob = dl_predict(url,dl_model)
    h_score, h_reasons = heuristic_checks(url, domain, features)
    rep = reputation_check(domain)

    # =========================
    # 🧠 STRUCTURED REASONS
    # =========================
    reasons = {
        "positive": [],
        "negative": [],
        "neutral": []
    }

    # =========================
    # 🟢 POSITIVE SIGNALS
    # =========================
    if rep == "trusted":
        reasons["positive"].append("Domain is from a trusted source")

    if any(domain.endswith(d) for d in TRUSTED_DOMAINS):
        reasons["positive"].append("Matches trusted domain list")

    if features.get("legit_path", 0):
        reasons["positive"].append("Matches known service endpoint")

    if has_ssl(domain):
        reasons["positive"].append("Uses secure HTTPS connection")
    else:
        reasons["neutral"].append("Uses HTTP (no SSL)")

    # =========================
    # 🔴 NEGATIVE SIGNALS
    # =========================
    if features.get("fake_brand", 0):
        reasons["negative"].append("Impersonates a known brand")
        h_score += 0.4

    if features.get("brand_mismatch", 0):
        reasons["negative"].append("Domain does not match brand name")
        h_score += 0.4

    if features.get("domain_random", 0):
        reasons["negative"].append("Domain appears randomly generated")
        h_score += 0.3

    if features.get("has_encoding", 0):
        reasons["negative"].append("Contains encoded characters")
        h_score += 0.2

    if features.get("repeated_chars", 0):
        reasons["negative"].append("Contains repeated suspicious characters")
        h_score += 0.2

    # =========================
    # 🚨 HARD RULES (early exit)
    # =========================
    if "xn--" in domain:
        return "Phishing", 0.95, ["Suspicious encoded (punycode) domain"]

    if features.get("shortener", 0):
        return "Suspicious", 0.7, ["Uses URL shortening service"]

    if features.get("http_login", 0):
        return "Suspicious", 0.75, ["Login page over HTTP"]

    if has_ip(url):
        return "Suspicious", 0.7, ["Uses IP address instead of domain"]

    if google_safe_check(url) == 1:
        return "Phishing", 0.99, ["Blacklisted by Google Safe Browsing"]

    # =========================
    # ⚠️ SOFT SIGNALS
    # =========================
    if has_dns(domain) == 0:
        reasons["neutral"].append("Domain could not be verified")
        h_score += 0.2

    age = domain_age(domain)
    if age != -1 and age < 180:
        reasons["negative"].append("Recently registered domain")
        h_score += 0.2

    # 🔥 KEYWORD DETECTION (FIXED)
    suspicious_words = ["secure", "login", "verify", "account", "update", "portal"]
    keyword_count = sum(word in url.lower() for word in suspicious_words)

    if keyword_count > 0:
        reasons["negative"].append("Contains suspicious security-related keywords")
        h_score += 0.3

    # =========================
    # 🚨 STRONG COMBO RULES
    # =========================
    if features.get("fake_brand", 0) and features.get("brand_mismatch", 0):
        return "Phishing", 0.95, [
            "Strong brand impersonation detected",
            "Domain does not match official brand"
        ]

    if keyword_count >= 2 and features.get("domain_random", 0):
        return "Phishing", 0.95, [
            "Multiple phishing keywords + random domain"
        ]

    if features.get("fake_brand", 0) and keyword_count >= 1:
        return "Phishing", 0.95, [
            "Brand impersonation with phishing keywords"
        ]
     # 🚨 STRONG PHISHING COMBO RULE
    if (
        features.get("fake_brand", 0) == 1 or
        features.get("brand_mismatch", 0) == 1
    ) and (
        features.get("num_keywords", 0) >= 2 or
        features.get("http_login", 0) == 1 or
        features.get("domain_random", 0) == 1
    ):
        return "Phishing", 0.95, [
            "Brand impersonation + phishing keywords",
            "High-risk domain pattern detected"
        ]   
     # 🚨 STRONG HEURISTIC OVERRIDE (improved)
    if h_score >= 0.7:
        if (
            features.get("num_keywords", 0) >= 2 or
            features.get("fake_brand", 0) == 1 or
            features.get("brand_mismatch", 0) == 1
        ):
            return "Phishing", 0.9, [
                "High-risk domain with phishing patterns",
                "Suspicious keywords + brand misuse"
            ]
       # 🚨 BANK BRAND BOOST
    if any(bank in domain for bank in ["hdfc", "icici", "sbi"]):
        if features.get("num_keywords", 0) >= 1:
            return "Phishing", 0.95, [
                "Bank-related domain with phishing keywords"
            ]  
     # 🚨 SHORTENER + PHISHING INTENT
    if features.get("shortener", 0) == 1:
        if features.get("num_keywords", 0) >= 1:
            return "Phishing", 0.95, [
                "Shortened URL hiding phishing content",
                "Contains security-related keywords"
            ]
        return "Suspicious", 0.7, ["Uses URL shortening service"]  
     # 🚨 HIGH ML/DL CONFIDENCE OVERRIDE
    if prob > 0.9 and dl_prob > 0.9:
        return "Phishing", 0.95, [
            "Model strongly predicts phishing",
            "High confidence from ML and DL models"
        ]  
         # 🚨 SHORTENER HARD OVERRIDE
    if any(s in domain for s in ["tinyurl.com", "bit.ly"]):
        if features.get("num_keywords", 0) >= 1:
            return "Phishing", 0.95, [
                "Shortened URL hiding phishing intent"
                ]
         # 🚨 STRONG HEURISTIC OVERRIDE (FINAL FIX)
    if h_score >= 0.7:
        return "Phishing", 0.9, [
            "High-risk domain detected",
            "Multiple phishing indicators present"
        ]
    
    # 🚨 KEYWORD-ONLY PHISHING (modern attacks)
    if features.get("num_keywords", 0) >= 3:
        return "Phishing", 0.85, [
            "Excessive phishing-related keywords",
            "Likely social engineering attack"
        ]       
        # 🚨 KEYWORD-BASED PHISHING (FINAL FIX)
    if features.get("num_keywords", 0) >= 2:
        return "Phishing", 0.85, [
            "Multiple suspicious security-related keywords",
            "Likely phishing or social engineering URL"
        ]
    
    # =========================
    # ⚖️ FINAL SCORING (ML + DL + Heuristics)
    # =========================
    dl_prob = dl_predict(url,dl_model)

    risk_score = 0.3 * prob + 0.4 * dl_prob + 0.3 * h_score

    print("DEBUG → prob:", prob, "dl:", dl_prob, "h_score:", h_score, "risk:", risk_score)

    risk_score = max(0, min(risk_score, 1))

    # =========================
    # 🎯 FINAL LABEL
    # =========================
    if risk_score >= 0.84:
        label = "Phishing"
    elif risk_score >= 0.53:
        label = "Suspicious"
    else:
        label = "Legitimate"

    # =========================
    # 📊 CONFIDENCE
    # =========================
    if label == "Phishing":
        confidence = risk_score
    elif label == "Suspicious":
        confidence = 0.5 + (risk_score / 2)
    else:
        confidence = 1 - risk_score

    # =========================
    # 🧠 FALLBACK
    # =========================
    if label == "Legitimate" and not reasons["positive"]:
        reasons["neutral"].append("No strong phishing indicators detected")

    # =========================
    # 📌 MODEL INFO
    # =========================
    reasons["neutral"].append(f"Model confidence: {round(prob, 2)}")

    # =========================
    # 🧾 FORMAT OUTPUT
    # =========================
    final_reasons = []

    if reasons["positive"]:
        final_reasons.append("Positive indicators:")
        final_reasons += ["+ " + r for r in reasons["positive"]]

    if reasons["negative"]:
        final_reasons.append("Risk indicators:")
        final_reasons += ["- " + r for r in reasons["negative"]]

    if reasons["neutral"]:
        final_reasons.append("Additional info:")
        final_reasons += ["• " + r for r in reasons["neutral"]]

    return label, round(confidence, 2), final_reasons


def analyze_url(url,calibrated_model):
    url = normalize_url(url)  # 🔥 FIX HERE
    
    label, prob, features = predict_url(url, calibrated_model)
    reasons = explain_prediction(features)

    return {
        "url": url,
        "prediction": label,
        "confidence": round(prob * 100, 2),
        "reasons": reasons
    }

def dl_predict(url,dl_model):
    seq = tokenizer.texts_to_sequences([url])
    pad = pad_sequences(seq, maxlen=100)
    prob = dl_model.predict(pad)[0][0]
    return prob



   
    
    
    
    
    
    
        

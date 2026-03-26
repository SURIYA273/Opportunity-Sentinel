import ssl
import socket
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests
import whois
from bs4 import BeautifulSoup

import warnings
warnings.filterwarnings("ignore")


# ─── Keyword Lists ────────────────────────────────────────────────────────────

# Rule 2: Weighted scam word list — each match costs 10 points
SCAM_WORDS = [
    "urgent",
    "fee",
    "deposit",
    "win",
    "guaranteed",
    "aadhaar",
    "aadhar",
    "ssn",
    "bank password",
    "security deposit",
    "processing fee",
    "registration fee",
    "bank details",
    "upfront payment",
    "advance fee",
    "application fee",
    "payment required",
    "wire transfer",
    "send money",
    "pay first",
    "refundable deposit",
    "training fee",
    "kit fee",
    "material fee",
    "immediate joining",
    "limited seats",
    "no interview required",
    "guaranteed selection",
    "hurry up",
    "last few seats",
    "apply now before",
    "offer expires",
    "100% placement",
    "guaranteed job",
    "no experience required",
    "work from home guaranteed",
    "earn lakhs",
    "earn thousands daily",
    "free laptop",
    "free iphone",
    "you have been selected",
    "congratulations you won",
]

LOGIN_HEADERS = ["login", "sign in", "sign up", "register", "create account", "log in"]

TRUSTED_EXTENSIONS = [".edu", ".gov", ".org", ".ac", ".ac.in", ".edu.in"]
RISKY_EXTENSIONS = [".xyz", ".top", ".click", ".loan", ".win", ".stream", ".download", ".gq", ".cf", ".ml", ".tk"]

FREE_SSL_PROVIDERS = [
    "let's encrypt",
    "letsencrypt",
    "zerossl",
    "buypass",
    "ssl.com free",
    "sectigo free",
]


# ─── SSL Check ────────────────────────────────────────────────────────────────

def check_ssl(hostname: str, port: int = 443) -> dict:
    """Returns a dict with: valid, expired, free_provider, issuer, message"""
    result = {
        "valid": False,
        "expired": False,
        "free_provider": False,
        "issuer": "",
        "message": "",
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    result["message"] = "SSL certificate could not be verified"
                    return result

                result["valid"] = True

                # Extract issuer
                issuer_fields = dict(x[0] for x in cert.get("issuer", []))
                org = issuer_fields.get("organizationName", "")
                cn = issuer_fields.get("commonName", "")
                result["issuer"] = org or cn

                issuer_lower = (org + " " + cn).lower()
                if any(fp in issuer_lower for fp in FREE_SSL_PROVIDERS):
                    result["free_provider"] = True

                # Check expiry
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        if expiry < datetime.now(timezone.utc):
                            result["expired"] = True
                            result["valid"] = False
                            result["message"] = f"SSL certificate expired on {expiry.strftime('%Y-%m-%d')}"
                            return result
                    except ValueError:
                        pass

                if result["free_provider"]:
                    result["message"] = f"SSL certificate is valid but issued by a free provider ({org or cn}). Common among quick-setup scam sites."
                else:
                    result["message"] = f"Valid SSL certificate from {org or cn}."
                return result

    except ssl.SSLCertVerificationError:
        result["message"] = "SSL certificate verification failed (invalid or untrusted certificate)"
        return result
    except ssl.SSLError as e:
        result["message"] = f"SSL error: {str(e)}"
        return result
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        result["message"] = "Could not connect to host for SSL check"
        return result
    except Exception as e:
        result["message"] = f"SSL check error: {str(e)}"
        return result


# ─── WHOIS / Domain Age ───────────────────────────────────────────────────────

def get_domain_age(domain: str) -> tuple[Optional[int], str]:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if creation_date is None:
            return None, "WHOIS data missing — domain registration date unavailable"

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days
        return age_days, f"Domain registered {age_days} days ago"
    except Exception as e:
        return None, f"WHOIS lookup failed: {str(e)[:120]}"


# ─── Page Fetch ───────────────────────────────────────────────────────────────

def fetch_page_content(url: str) -> tuple[Optional[str], Optional[BeautifulSoup], str]:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True, verify=False)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "lxml")
        text = soup.get_text(separator=" ", strip=True).lower()
        return text, soup, "Page fetched successfully"
    except requests.exceptions.SSLError:
        return None, None, "SSL error when fetching page"
    except requests.exceptions.Timeout:
        return None, None, "Request timed out"
    except requests.exceptions.ConnectionError:
        return None, None, "Connection error (host unreachable)"
    except requests.exceptions.HTTPError as e:
        return None, None, f"HTTP error: {e.response.status_code}"
    except Exception as e:
        return None, None, f"Fetch error: {str(e)[:100]}"


# ─── Keyword Detection ────────────────────────────────────────────────────────

def detect_scam_keywords(text: str) -> list[str]:
    """Rule 2: scan for every word in SCAM_WORDS, return all matches."""
    found = []
    for word in SCAM_WORDS:
        if word in text and word not in found:
            found.append(word)
    return found


# ─── Input Field Analysis ─────────────────────────────────────────────────────

def analyze_inputs(soup: Optional[BeautifulSoup]) -> tuple[int, bool]:
    """
    Returns (total_input_count, has_login_header).
    Rule 3: >3 inputs with no login/signup header = data harvesting penalty.
    """
    if soup is None:
        return 0, False

    total_inputs = len(soup.find_all("input"))

    # Look for login/sign-up headings in h1-h4, button text, labels, and nav links
    page_text = soup.get_text(separator=" ", strip=True).lower()
    has_login = any(phrase in page_text for phrase in LOGIN_HEADERS)

    return total_inputs, has_login


# ─── Domain Reputation ────────────────────────────────────────────────────────

def assess_domain_reputation(domain: str) -> tuple[str, bool, bool]:
    domain_lower = domain.lower()
    for ext in TRUSTED_EXTENSIONS:
        if domain_lower.endswith(ext):
            return ext, True, False
    for ext in RISKY_EXTENSIONS:
        if domain_lower.endswith(ext):
            return ext, False, True
    parts = domain_lower.split(".")
    if len(parts) >= 2:
        return "." + parts[-1], False, False
    return "", False, False


# ─── Scoring Engine ───────────────────────────────────────────────────────────

def calculate_score_and_grade(
    ssl_info: dict,
    domain_age_days: Optional[int],
    scam_keywords: list[str],
    total_input_count: int,
    has_login_header: bool,
    is_trusted_domain: bool,
    is_risky_domain: bool,
    fetch_failed: bool,
) -> tuple[int, str, list[dict], str]:

    score = 100
    flags = []

    # ── Rule 4: SSL Check ────────────────────────────────────────────────────
    if not ssl_info["valid"]:
        score -= 25
        flags.append({
            "category": "SSL Certificate",
            "severity": "high",
            "message": f"No valid SSL — {ssl_info['message']} This is a serious security risk.",
        })
    elif ssl_info["expired"]:
        score -= 25
        flags.append({
            "category": "SSL Certificate",
            "severity": "high",
            "message": ssl_info["message"],
        })
    elif ssl_info["free_provider"]:
        # Rule 4: Free provider (Let's Encrypt etc.) → Caution, -10
        score -= 10
        flags.append({
            "category": "SSL Certificate",
            "severity": "medium",
            "message": f"Caution: SSL certificate issued by a free provider ({ssl_info['issuer']}). "
                       "While free SSL is legitimate, it is also commonly used by scam sites for a quick setup.",
        })
    else:
        flags.append({
            "category": "SSL Certificate",
            "severity": "low",
            "message": f"Valid SSL certificate from {ssl_info['issuer']}. Site uses HTTPS encryption.",
        })

    # ── Rule 1: Strict Domain Age ─────────────────────────────────────────────
    if domain_age_days is None:
        # WHOIS data missing → -50 immediately
        score -= 50
        flags.append({
            "category": "Domain Age",
            "severity": "high",
            "message": "HIGH RISK: WHOIS data is missing or the domain is privacy-protected. "
                       "Scam sites routinely hide registration info. Deducted 50 points.",
        })
    elif domain_age_days < 180:
        # Under 6 months → -50 immediately
        score -= 50
        flags.append({
            "category": "Domain Age",
            "severity": "high",
            "message": f"HIGH RISK: Domain is only {domain_age_days} day(s) old (under 6 months). "
                       "Fraudulent sites are typically created days or weeks before a scam campaign. Deducted 50 points.",
        })
    elif domain_age_days < 365:
        score -= 10
        flags.append({
            "category": "Domain Age",
            "severity": "medium",
            "message": f"Caution: Domain is {domain_age_days} days old (under 1 year). Proceed carefully.",
        })
    else:
        flags.append({
            "category": "Domain Age",
            "severity": "low",
            "message": f"Domain has been registered for {domain_age_days} days "
                       f"({domain_age_days // 365} year(s)). Established age is a positive signal.",
        })

    # ── Rule 2: Keyword Weighting — 10 pts per match ──────────────────────────
    if scam_keywords:
        deduction = len(scam_keywords) * 10
        score -= deduction
        flags.append({
            "category": "Scam Keywords",
            "severity": "high" if deduction >= 30 else "medium",
            "message": f"Alert: {len(scam_keywords)} scam indicator(s) found: "
                       f"'{', '.join(scam_keywords[:5])}{'...' if len(scam_keywords) > 5 else ''}'. "
                       f"Deducted {deduction} points ({len(scam_keywords)} × 10).",
        })
    elif not fetch_failed:
        flags.append({
            "category": "Scam Keywords",
            "severity": "low",
            "message": "No scam keywords detected in the page content. Good sign.",
        })

    # ── Rule 3: Input Field Penalty ───────────────────────────────────────────
    if total_input_count > 3 and not has_login_header:
        score -= 20
        flags.append({
            "category": "Data Harvesting",
            "severity": "high",
            "message": f"Alert: {total_input_count} input fields found but no Login/Sign-Up context detected. "
                       "This pattern suggests aggressive data harvesting. Deducted 20 points.",
        })
    elif total_input_count > 3 and has_login_header:
        flags.append({
            "category": "Data Harvesting",
            "severity": "low",
            "message": f"Found {total_input_count} input fields within a login/registration context. Appears normal.",
        })
    elif not fetch_failed:
        flags.append({
            "category": "Data Harvesting",
            "severity": "low",
            "message": f"Found {total_input_count} input field(s). Data collection appears reasonable.",
        })

    # ── Domain Reputation ─────────────────────────────────────────────────────
    if is_trusted_domain:
        score = min(100, score + 5)
        flags.append({
            "category": "Domain Reputation",
            "severity": "low",
            "message": "Trusted domain extension (.edu, .gov, or .org). These are regulated and more trustworthy.",
        })
    elif is_risky_domain:
        score -= 15
        flags.append({
            "category": "Domain Reputation",
            "severity": "high",
            "message": "High-risk domain extension (.xyz, .top, .click, etc.). Frequently used by scam sites.",
        })
    else:
        flags.append({
            "category": "Domain Reputation",
            "severity": "low",
            "message": "Standard domain extension. Neither a strong trust signal nor a red flag.",
        })

    # ── Page Accessibility ────────────────────────────────────────────────────
    if fetch_failed:
        score -= 5
        flags.append({
            "category": "Page Accessibility",
            "severity": "medium",
            "message": "Could not fetch page content — keyword and input checks were skipped.",
        })

    # ── Final clamp & grade ───────────────────────────────────────────────────
    score = max(0, min(100, score))

    if score >= 85:
        grade = "A+"
    elif score >= 75:
        grade = "A"
    elif score >= 65:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 35:
        grade = "D"
    else:
        grade = "F"

    # Rule 5: below 50 → HIGH RISK label in summary
    if score < 50:
        summary = f"⚠️ HIGH RISK — Trust score is {score}/100. Multiple serious red flags detected. Do NOT share personal data or money."
    elif score < 65:
        summary = f"Suspicious activity detected. Trust score: {score}/100. Verify this opportunity through official channels before proceeding."
    elif score < 80:
        summary = f"Some warning signs present. Trust score: {score}/100. Proceed with caution."
    else:
        summary = f"This opportunity appears relatively safe. Trust score: {score}/100."

    return score, grade, flags, summary


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def analyze_url(url: str) -> dict:
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    hostname = parsed.hostname or ""
    domain = hostname.lstrip("www.")

    ssl_info = check_ssl(hostname)

    domain_age_days, _ = get_domain_age(domain)

    page_text, soup, _ = fetch_page_content(url)
    fetch_failed = page_text is None

    scam_keywords = detect_scam_keywords(page_text or "")

    total_input_count, has_login_header = analyze_inputs(soup)

    domain_extension, is_trusted_domain, is_risky_domain = assess_domain_reputation(domain)

    trust_score, grade, flags, summary = calculate_score_and_grade(
        ssl_info=ssl_info,
        domain_age_days=domain_age_days,
        scam_keywords=scam_keywords,
        total_input_count=total_input_count,
        has_login_header=has_login_header,
        is_trusted_domain=is_trusted_domain,
        is_risky_domain=is_risky_domain,
        fetch_failed=fetch_failed,
    )

    return {
        "url": url,
        "trustScore": trust_score,
        "grade": grade,
        "flags": flags,
        "sslValid": ssl_info["valid"],
        "domainAgeDays": domain_age_days,
        "domainExtension": domain_extension,
        "inputFieldCount": float(total_input_count),
        "scamKeywordsFound": scam_keywords,
        "summary": summary,
    }

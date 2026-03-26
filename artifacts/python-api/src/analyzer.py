import ssl
import socket
import re
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import requests
import whois
from bs4 import BeautifulSoup


FINANCIAL_SCAM_PHRASES = [
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
]

FAKE_URGENCY_PHRASES = [
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
]

SENSITIVE_INPUT_KEYWORDS = [
    "ssn",
    "social security",
    "aadhaar",
    "aadhar",
    "pan card",
    "bank account",
    "credit card",
    "debit card",
    "ifsc",
    "routing number",
    "passport",
    "date of birth",
    "mother's maiden",
]

TRUSTED_EXTENSIONS = [".edu", ".gov", ".org", ".ac", ".ac.in", ".edu.in"]
RISKY_EXTENSIONS = [".xyz", ".top", ".click", ".loan", ".win", ".stream", ".download", ".gq", ".cf", ".ml", ".tk"]


def check_ssl(hostname: str, port: int = 443) -> tuple[bool, str]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return True, "Valid SSL certificate found"
                return False, "SSL certificate could not be verified"
    except ssl.SSLCertVerificationError:
        return False, "SSL certificate verification failed (invalid or untrusted certificate)"
    except ssl.SSLError as e:
        return False, f"SSL error: {str(e)}"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return False, "Could not connect to host for SSL check"
    except Exception as e:
        return False, f"SSL check error: {str(e)}"


def get_domain_age(domain: str) -> tuple[Optional[int], str]:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if creation_date is None:
            return None, "Domain registration date not available"

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
            age_days = (now - creation_date).days
        else:
            age_days = (now - datetime.now(timezone.utc)).days

        return age_days, f"Domain registered {age_days} days ago"
    except Exception as e:
        return None, f"WHOIS lookup failed: {str(e)[:100]}"


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


def detect_scam_keywords(text: str) -> list[str]:
    found = []
    for phrase in FINANCIAL_SCAM_PHRASES:
        if phrase in text:
            found.append(phrase)
    for phrase in FAKE_URGENCY_PHRASES:
        if phrase in text:
            found.append(phrase)
    return found


def count_sensitive_inputs(soup: BeautifulSoup) -> int:
    if soup is None:
        return 0
    inputs = soup.find_all("input")
    count = 0
    for inp in inputs:
        input_text = " ".join([
            str(inp.get("name", "")),
            str(inp.get("id", "")),
            str(inp.get("placeholder", "")),
            str(inp.get("label", "")),
            str(inp.get("type", "")),
        ]).lower()
        for kw in SENSITIVE_INPUT_KEYWORDS:
            if kw in input_text:
                count += 1
                break
    return count


def assess_domain_reputation(domain: str) -> tuple[str, bool, bool]:
    domain_lower = domain.lower()
    is_trusted = any(domain_lower.endswith(ext) for ext in TRUSTED_EXTENSIONS)
    is_risky = any(domain_lower.endswith(ext) for ext in RISKY_EXTENSIONS)
    
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


def calculate_score_and_grade(
    ssl_valid: bool,
    domain_age_days: Optional[int],
    scam_keywords: list[str],
    sensitive_input_count: int,
    is_trusted_domain: bool,
    is_risky_domain: bool,
    fetch_failed: bool,
) -> tuple[int, str, list[dict], str]:
    score = 100
    flags = []

    if not ssl_valid:
        score -= 25
        flags.append({
            "category": "SSL Certificate",
            "severity": "high",
            "message": "No valid SSL certificate found. The site is not using HTTPS encryption, which is a serious security risk.",
        })
    else:
        flags.append({
            "category": "SSL Certificate",
            "severity": "low",
            "message": "Valid SSL certificate detected. The site uses HTTPS encryption.",
        })

    if domain_age_days is not None:
        if domain_age_days < 30:
            score -= 30
            flags.append({
                "category": "Domain Age",
                "severity": "high",
                "message": f"Warning: Domain is only {domain_age_days} days old. Scam sites are often created just before launching a fraud campaign.",
            })
        elif domain_age_days < 180:
            score -= 20
            flags.append({
                "category": "Domain Age",
                "severity": "medium",
                "message": f"Caution: Domain is only {domain_age_days} days old (less than 6 months). Newer domains are higher risk.",
            })
        elif domain_age_days < 365:
            score -= 5
            flags.append({
                "category": "Domain Age",
                "severity": "low",
                "message": f"Domain is {domain_age_days} days old (less than 1 year). Proceed with some caution.",
            })
        else:
            flags.append({
                "category": "Domain Age",
                "severity": "low",
                "message": f"Domain has been registered for {domain_age_days} days ({domain_age_days // 365} year(s)). Established domain age is a positive signal.",
            })
    else:
        score -= 10
        flags.append({
            "category": "Domain Age",
            "severity": "medium",
            "message": "Could not determine domain registration date. This may indicate a newly registered or privacy-protected domain.",
        })

    if scam_keywords:
        financial_found = [k for k in scam_keywords if k in FINANCIAL_SCAM_PHRASES]
        urgency_found = [k for k in scam_keywords if k in FAKE_URGENCY_PHRASES]

        if financial_found:
            deduction = min(30, len(financial_found) * 10)
            score -= deduction
            flags.append({
                "category": "Financial Red Flags",
                "severity": "high",
                "message": f"Alert: Phrases related to upfront fees found: '{', '.join(financial_found[:3])}'. Legitimate opportunities NEVER ask for money.",
            })

        if urgency_found:
            deduction = min(15, len(urgency_found) * 5)
            score -= deduction
            flags.append({
                "category": "Fake Urgency",
                "severity": "medium",
                "message": f"Warning: Fake urgency language detected: '{', '.join(urgency_found[:3])}'. This is a classic scam pressure tactic.",
            })
    elif not fetch_failed:
        flags.append({
            "category": "Scam Keywords",
            "severity": "low",
            "message": "No common scam phrases detected in the page content.",
        })

    if sensitive_input_count > 5:
        score -= 20
        flags.append({
            "category": "Data Harvesting",
            "severity": "high",
            "message": f"Alert: Found {sensitive_input_count} sensitive data fields (SSN, Aadhaar, bank info, etc.). An informational page should never collect this much personal data.",
        })
    elif sensitive_input_count > 2:
        score -= 10
        flags.append({
            "category": "Data Harvesting",
            "severity": "medium",
            "message": f"Caution: Found {sensitive_input_count} potentially sensitive input fields. Review what personal information is being requested.",
        })
    elif not fetch_failed:
        flags.append({
            "category": "Data Harvesting",
            "severity": "low",
            "message": f"Found {sensitive_input_count} sensitive input field(s). Data collection appears reasonable.",
        })

    if is_trusted_domain:
        score = min(100, score + 5)
        flags.append({
            "category": "Domain Reputation",
            "severity": "low",
            "message": "Trusted domain extension (.edu, .gov, or .org) detected. These are regulated and generally more trustworthy.",
        })
    elif is_risky_domain:
        score -= 15
        flags.append({
            "category": "Domain Reputation",
            "severity": "high",
            "message": "High-risk domain extension detected (.xyz, .top, .click, etc.). These extensions are frequently used by scam sites.",
        })
    else:
        flags.append({
            "category": "Domain Reputation",
            "severity": "low",
            "message": "Standard domain extension. Neither a strong trust signal nor a red flag.",
        })

    if fetch_failed:
        score -= 5
        flags.append({
            "category": "Page Accessibility",
            "severity": "medium",
            "message": "Could not fetch page content for analysis. Content-based checks were skipped.",
        })

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

    if score >= 75:
        summary = f"This opportunity appears relatively safe with a trust score of {score}/100."
    elif score >= 50:
        summary = f"This opportunity has some warning signs. Proceed carefully — trust score is {score}/100."
    elif score >= 35:
        summary = f"Multiple red flags detected. This opportunity is likely a scam — trust score is {score}/100."
    else:
        summary = f"High scam probability detected! Do NOT share personal information or money. Trust score: {score}/100."

    return score, grade, flags, summary


def analyze_url(url: str) -> dict:
    import warnings
    warnings.filterwarnings("ignore")

    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)

    hostname = parsed.hostname or ""
    domain = hostname.lstrip("www.")

    ssl_valid, ssl_message = check_ssl(hostname)

    domain_age_days, domain_age_message = get_domain_age(domain)

    page_text, soup, fetch_message = fetch_page_content(url)
    fetch_failed = page_text is None

    scam_keywords = detect_scam_keywords(page_text or "")

    sensitive_input_count = count_sensitive_inputs(soup)
    total_input_count = len(soup.find_all("input")) if soup else 0

    domain_extension, is_trusted_domain, is_risky_domain = assess_domain_reputation(domain)

    trust_score, grade, flags, summary = calculate_score_and_grade(
        ssl_valid=ssl_valid,
        domain_age_days=domain_age_days,
        scam_keywords=scam_keywords,
        sensitive_input_count=sensitive_input_count,
        is_trusted_domain=is_trusted_domain,
        is_risky_domain=is_risky_domain,
        fetch_failed=fetch_failed,
    )

    return {
        "url": url,
        "trustScore": trust_score,
        "grade": grade,
        "flags": flags,
        "sslValid": ssl_valid,
        "domainAgeDays": domain_age_days,
        "domainExtension": domain_extension,
        "inputFieldCount": sensitive_input_count,
        "scamKeywordsFound": scam_keywords,
        "summary": summary,
    }

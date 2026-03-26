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


# ─── Whitelists ───────────────────────────────────────────────────────────────

# Manual trusted domain whitelist — always get a +50 boost
TRUSTED_DOMAINS = [
    "mahendra.info",
    "mahendra.org",
    "wikipedia.org",
    "mit.edu",
    "stanford.edu",
]

# Extensions that are whitelisted — no reputation penalty
TRUSTED_EXTENSIONS = [".edu", ".gov", ".org", ".ac", ".ac.in", ".edu.in", ".info"]

# Risky extensions — still penalised
RISKY_EXTENSIONS = [".xyz", ".top", ".click", ".loan", ".win", ".stream", ".download", ".gq", ".cf", ".ml", ".tk"]

FREE_SSL_PROVIDERS = [
    "let's encrypt", "letsencrypt", "zerossl",
    "buypass", "ssl.com free", "sectigo free",
]

# ─── Keyword Lists ────────────────────────────────────────────────────────────

# Educational context words — if these appear NEAR a scam word, skip the penalty
EDUCATIONAL_CONTEXT_WORDS = [
    "admission", "college", "university", "courses", "curriculum",
    "semester", "tuition", "campus", "academic", "faculty",
    "scholarship", "enrollment", "department", "degree", "programme",
    "program", "school", "institute", "polytechnic",
]

# Context window (characters around a match to check for educational words)
CONTEXT_WINDOW = 300

# Scam words that are context-sensitive (penalised only OUTSIDE educational context)
CONTEXT_SENSITIVE_WORDS = [
    "fee", "registration fee", "deposit", "guaranteed", "urgent",
    "registration", "application fee",
]

# Scam words that are ALWAYS penalised regardless of context
HARD_SCAM_WORDS = [
    "aadhaar", "aadhar", "ssn", "bank password",
    "security deposit", "processing fee",
    "bank details", "upfront payment", "advance fee",
    "payment required", "wire transfer", "send money",
    "pay first", "refundable deposit", "training fee",
    "kit fee", "material fee", "immediate joining",
    "no interview required", "guaranteed selection",
    "hurry up", "last few seats", "apply now before",
    "offer expires", "100% placement", "guaranteed job",
    "no experience required", "work from home guaranteed",
    "earn lakhs", "earn thousands daily",
    "free laptop", "free iphone",
    "you have been selected", "congratulations you won",
    "win",
]

LOGIN_HEADERS = ["login", "sign in", "sign up", "register", "create account", "log in"]


# ─── Helper: is domain trusted? ───────────────────────────────────────────────

def is_trusted_domain_name(domain: str) -> bool:
    domain_lower = domain.lower().lstrip("www.")
    return any(domain_lower == td or domain_lower.endswith("." + td) for td in TRUSTED_DOMAINS)


def get_trusted_domain_match(domain: str) -> Optional[str]:
    domain_lower = domain.lower().lstrip("www.")
    for td in TRUSTED_DOMAINS:
        if domain_lower == td or domain_lower.endswith("." + td):
            return td
    return None


# ─── SSL Check ────────────────────────────────────────────────────────────────

def check_ssl(hostname: str, port: int = 443) -> dict:
    result = {"valid": False, "expired": False, "free_provider": False, "issuer": "", "message": ""}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    result["message"] = "SSL certificate could not be verified"
                    return result

                result["valid"] = True
                issuer_fields = dict(x[0] for x in cert.get("issuer", []))
                org = issuer_fields.get("organizationName", "")
                cn = issuer_fields.get("commonName", "")
                result["issuer"] = org or cn
                issuer_lower = (org + " " + cn).lower()
                if any(fp in issuer_lower for fp in FREE_SSL_PROVIDERS):
                    result["free_provider"] = True

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
                    result["message"] = f"SSL valid but issued by a free provider ({org or cn}). Common among quick-setup scam sites."
                else:
                    result["message"] = f"Valid SSL certificate from {org or cn}."
                return result

    except ssl.SSLCertVerificationError:
        result["message"] = "SSL verification failed (invalid or untrusted certificate)"
    except ssl.SSLError as e:
        result["message"] = f"SSL error: {str(e)}"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        result["message"] = "Could not connect to host for SSL check"
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
        age_days = (datetime.now(timezone.utc) - creation_date).days
        return age_days, f"Domain registered {age_days} days ago"
    except Exception as e:
        return None, f"WHOIS lookup failed: {str(e)[:120]}"


# ─── Page Fetch ───────────────────────────────────────────────────────────────

def fetch_page_content(url: str) -> tuple[Optional[str], Optional[BeautifulSoup], str]:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
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


# ─── Contextual Keyword Detection ─────────────────────────────────────────────

def is_in_educational_context(text: str, match_start: int) -> bool:
    """Check if a match position is surrounded by educational context words."""
    window_start = max(0, match_start - CONTEXT_WINDOW)
    window_end = min(len(text), match_start + CONTEXT_WINDOW)
    window = text[window_start:window_end]
    return any(ctx_word in window for ctx_word in EDUCATIONAL_CONTEXT_WORDS)


def detect_scam_keywords(text: str) -> tuple[list[str], list[str]]:
    """
    Returns (penalised_matches, context_skipped_matches).
    - Hard scam words are always penalised.
    - Context-sensitive words are skipped if near educational terms.
    """
    penalised = []
    skipped = []

    for word in HARD_SCAM_WORDS:
        if word in text and word not in penalised:
            penalised.append(word)

    for word in CONTEXT_SENSITIVE_WORDS:
        if word in text and word not in penalised and word not in skipped:
            idx = text.find(word)
            if is_in_educational_context(text, idx):
                skipped.append(word)
            else:
                penalised.append(word)

    return penalised, skipped


# ─── Input Field Analysis ─────────────────────────────────────────────────────

def analyze_inputs(soup: Optional[BeautifulSoup]) -> tuple[int, bool]:
    if soup is None:
        return 0, False
    total_inputs = len(soup.find_all("input"))
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
    ext = "." + parts[-1] if len(parts) >= 2 else ""
    return ext, False, False


# ─── Scoring Engine ───────────────────────────────────────────────────────────

def calculate_score_and_grade(
    ssl_info: dict,
    domain_age_days: Optional[int],
    penalised_keywords: list[str],
    skipped_keywords: list[str],
    total_input_count: int,
    has_login_header: bool,
    domain_extension: str,
    is_trusted_ext: bool,
    is_risky_ext: bool,
    fetch_failed: bool,
    trusted_domain_match: Optional[str],
) -> tuple[int, str, list[dict], str]:

    score = 100
    flags = []

    # ── Manual Whitelist Boost (+50) ─────────────────────────────────────────
    if trusted_domain_match:
        score = min(100, score + 50)
        flags.append({
            "category": "Trusted Domain",
            "severity": "low",
            "message": f"'{trusted_domain_match}' is on the trusted domain whitelist. +50 trust boost applied.",
        })

    # ── SSL Check ────────────────────────────────────────────────────────────
    if not ssl_info["valid"]:
        score -= 25
        flags.append({"category": "SSL Certificate", "severity": "high",
                       "message": f"No valid SSL — {ssl_info['message']} This is a serious security risk."})
    elif ssl_info["expired"]:
        score -= 25
        flags.append({"category": "SSL Certificate", "severity": "high", "message": ssl_info["message"]})
    elif ssl_info["free_provider"]:
        score -= 10
        flags.append({"category": "SSL Certificate", "severity": "medium",
                       "message": f"Caution: SSL issued by a free provider ({ssl_info['issuer']}). "
                                  "Common among newly-created or scam sites."})
    else:
        flags.append({"category": "SSL Certificate", "severity": "low",
                       "message": f"Valid SSL from {ssl_info['issuer']}. Site uses HTTPS encryption."})

    # ── Domain Age ───────────────────────────────────────────────────────────
    if domain_age_days is None:
        score -= 50
        flags.append({"category": "Domain Age", "severity": "high",
                       "message": "HIGH RISK: WHOIS data missing or domain is privacy-protected. "
                                  "Scam sites routinely hide registration info. −50 points."})
    elif domain_age_days < 180:
        score -= 50
        flags.append({"category": "Domain Age", "severity": "high",
                       "message": f"HIGH RISK: Domain is only {domain_age_days} day(s) old (under 6 months). "
                                  "Fraudulent sites are typically created shortly before a campaign. −50 points."})
    elif domain_age_days < 365:
        score -= 10
        flags.append({"category": "Domain Age", "severity": "medium",
                       "message": f"Caution: Domain is {domain_age_days} days old (under 1 year). Proceed carefully."})
    else:
        flags.append({"category": "Domain Age", "severity": "low",
                       "message": f"Domain registered {domain_age_days} days ago "
                                  f"({domain_age_days // 365} year(s)). Established age is a positive signal."})

    # ── Contextual Keywords ───────────────────────────────────────────────────
    if penalised_keywords:
        deduction = len(penalised_keywords) * 10
        score -= deduction
        flags.append({"category": "Scam Keywords", "severity": "high" if deduction >= 30 else "medium",
                       "message": f"Alert: {len(penalised_keywords)} scam indicator(s) found: "
                                  f"'{', '.join(penalised_keywords[:5])}{'...' if len(penalised_keywords) > 5 else ''}'. "
                                  f"−{deduction} points ({len(penalised_keywords)} × 10)."})
    elif not fetch_failed:
        flags.append({"category": "Scam Keywords", "severity": "low",
                       "message": "No scam keywords detected in the page content."})

    if skipped_keywords:
        flags.append({"category": "Scam Keywords", "severity": "low",
                       "message": f"Words like '{', '.join(skipped_keywords[:3])}' were found but appear in an "
                                  "educational context (near 'Admission', 'College', etc.) — no penalty applied."})

    # ── Input Field Penalty ───────────────────────────────────────────────────
    if total_input_count > 3 and not has_login_header:
        score -= 20
        flags.append({"category": "Data Harvesting", "severity": "high",
                       "message": f"Alert: {total_input_count} input fields found with no login/registration context. "
                                  "Possible aggressive data harvesting. −20 points."})
    elif total_input_count > 3:
        flags.append({"category": "Data Harvesting", "severity": "low",
                       "message": f"{total_input_count} input fields found within a login/registration context. Appears normal."})
    elif not fetch_failed:
        flags.append({"category": "Data Harvesting", "severity": "low",
                       "message": f"Found {total_input_count} input field(s). Data collection appears reasonable."})

    # ── Domain Reputation ─────────────────────────────────────────────────────
    if is_trusted_ext:
        score = min(100, score + 5)
        flags.append({"category": "Domain Reputation", "severity": "low",
                       "message": f"Trusted extension ({domain_extension}) — whitelisted, no penalty. "
                                  "These domains are regulated and generally more trustworthy."})
    elif is_risky_ext:
        score -= 15
        flags.append({"category": "Domain Reputation", "severity": "high",
                       "message": f"High-risk extension ({domain_extension}) frequently used by scam sites. −15 points."})
    else:
        flags.append({"category": "Domain Reputation", "severity": "low",
                       "message": f"Standard extension ({domain_extension}). Neither a strong trust signal nor a red flag."})

    # ── Page Accessibility ────────────────────────────────────────────────────
    if fetch_failed:
        score -= 5
        flags.append({"category": "Page Accessibility", "severity": "medium",
                       "message": "Could not fetch page content — keyword and input checks were skipped."})

    # ── Final clamp & grade ───────────────────────────────────────────────────
    score = max(0, min(100, score))

    if score >= 85:   grade = "A+"
    elif score >= 75: grade = "A"
    elif score >= 65: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 35: grade = "D"
    else:             grade = "F"

    if score < 50:
        summary = f"⚠️ HIGH RISK — Trust score {score}/100. Multiple serious red flags. Do NOT share personal data or money."
    elif score < 65:
        summary = f"Suspicious signals detected. Trust score: {score}/100. Verify through official channels before proceeding."
    elif score < 80:
        summary = f"Some warning signs present. Trust score: {score}/100. Proceed with caution."
    else:
        summary = f"This opportunity appears relatively safe. Trust score: {score}/100."

    return score, grade, flags, summary


# ─── Next Steps Generator (URL) ───────────────────────────────────────────────

def generate_url_next_steps(score: int, flags: list, domain: str, domain_age_days, ssl_info: dict) -> list:
    """Generate prioritized, actionable next-step recommendations for URL analysis."""
    steps = []
    high_cats = {f["category"] for f in flags if f["severity"] == "high"}
    med_cats = {f["category"] for f in flags if f["severity"] == "medium"}
    all_risk_cats = high_cats | med_cats

    if score < 35:
        steps.append({
            "priority": "critical",
            "action": "Stop — do NOT visit or interact with this site",
            "detail": f"'{domain}' shows multiple serious red flags. Do not click any links, fill in forms, or share any information."
        })
        steps.append({
            "priority": "critical",
            "action": "Report the scam website",
            "detail": "Report to cybercrime.gov.in or call 1930 (India Cybercrime Helpline). You can also report to Google Safe Browsing at safebrowsing.google.com/safebrowsing/report_phish/."
        })
    elif score < 50:
        steps.append({
            "priority": "high",
            "action": "Avoid sharing personal or financial information",
            "detail": f"'{domain}' has high-risk indicators. Never submit your Aadhaar, bank details, or pay any fees through this site."
        })
        steps.append({
            "priority": "high",
            "action": "Find the official website independently",
            "detail": "Search for the organization's name on Google. Verify the official domain from trusted directories, not links you received."
        })
    elif score < 65:
        steps.append({
            "priority": "medium",
            "action": "Cross-check through official sources",
            "detail": f"Verify '{domain}' by searching the organization on LinkedIn, Naukri, or Internshala before engaging."
        })

    # SSL issues
    if "SSL Certificate" in high_cats:
        steps.append({
            "priority": "critical",
            "action": "Never enter any data on this site",
            "detail": "This site has an invalid or missing SSL certificate. Any data you enter (passwords, card numbers) is transmitted without encryption and can be stolen."
        })
    elif ssl_info.get("free_provider"):
        steps.append({
            "priority": "medium",
            "action": "Be cautious about the SSL certificate",
            "detail": "The SSL certificate is from a free provider. While not conclusive, scam sites frequently use free SSL to appear legitimate quickly."
        })

    # Very new domain
    if domain_age_days is not None and domain_age_days < 180:
        steps.append({
            "priority": "critical",
            "action": "Treat this brand-new domain with extreme suspicion",
            "detail": f"'{domain}' was registered only {domain_age_days} day(s) ago. Fraudulent sites are created just before a campaign and abandoned afterward."
        })
    elif domain_age_days is None:
        steps.append({
            "priority": "high",
            "action": "Verify the domain independently",
            "detail": f"WHOIS data for '{domain}' is hidden or missing. Scam operators often hide domain registration details."
        })

    # Scam keywords
    if "Scam Keywords" in high_cats:
        steps.append({
            "priority": "critical",
            "action": "Refuse any payment or fee request",
            "detail": "Scam keywords were found in this page's content. No legitimate opportunity requires upfront deposits, processing fees, or security charges."
        })

    # Data harvesting
    if "Data Harvesting" in high_cats:
        steps.append({
            "priority": "high",
            "action": "Do not fill in any forms on this site",
            "detail": "An unusually high number of input fields were detected without a clear login or registration purpose — a sign of aggressive data harvesting."
        })

    # Risky domain extension
    if "Domain Reputation" in high_cats:
        steps.append({
            "priority": "high",
            "action": "Be extra wary of the domain extension",
            "detail": "This domain uses an extension commonly associated with scam and spam sites. Legitimate organizations typically use .com, .org, .edu, or country-specific extensions."
        })

    # Safe overall
    if score >= 75:
        steps.append({
            "priority": "low",
            "action": "Still verify through official channels",
            "detail": f"'{domain}' appears relatively safe, but always confirm the opportunity through the organization's officially published contact details."
        })

    return steps


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

    penalised_keywords, skipped_keywords = detect_scam_keywords(page_text or "")
    total_input_count, has_login_header = analyze_inputs(soup)
    domain_extension, is_trusted_ext, is_risky_ext = assess_domain_reputation(domain)
    trusted_domain_match = get_trusted_domain_match(domain)

    trust_score, grade, flags, summary = calculate_score_and_grade(
        ssl_info=ssl_info,
        domain_age_days=domain_age_days,
        penalised_keywords=penalised_keywords,
        skipped_keywords=skipped_keywords,
        total_input_count=total_input_count,
        has_login_header=has_login_header,
        domain_extension=domain_extension,
        is_trusted_ext=is_trusted_ext,
        is_risky_ext=is_risky_ext,
        fetch_failed=fetch_failed,
        trusted_domain_match=trusted_domain_match,
    )

    next_steps = generate_url_next_steps(trust_score, flags, domain, domain_age_days, ssl_info)

    return {
        "url": url,
        "trustScore": trust_score,
        "grade": grade,
        "flags": flags,
        "sslValid": ssl_info["valid"],
        "domainAgeDays": domain_age_days,
        "domainExtension": domain_extension,
        "inputFieldCount": float(total_input_count),
        "scamKeywordsFound": penalised_keywords,
        "summary": summary,
        "nextSteps": next_steps,
    }

"""
Text / Email analysis module.
Accepts raw pasted text (email body, social media post, job ad).
"""
import re
from analyzer import (
    HARD_SCAM_WORDS, CONTEXT_SENSITIVE_WORDS, EDUCATIONAL_CONTEXT_WORDS,
    is_in_educational_context, get_domain_age
)

FREE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "rediffmail.com", "ymail.com", "aol.com", "mail.com",
    "protonmail.com", "icloud.com", "me.com", "live.com",
    "zoho.com", "inbox.com", "fastmail.com",
]

URGENCY_PATTERNS = [
    r"within \d+ (hours?|days?|minutes?)",
    r"respond (immediately|urgently|asap|now)",
    r"limited (time|offer|seats?)",
    r"expires? (today|tonight|soon)",
    r"hurry",
    r"act now",
    r"don'?t miss",
    r"last (chance|opportunity|day)",
    r"deadline.{0,20}today",
    r"only \d+ (spots?|seats?|positions?) left",
]

FAKE_JOB_PATTERNS = [
    r"no (experience|qualification|degree) required",
    r"work from home.{0,30}(guaranteed|assured)",
    r"earn \$?\d+[\d,]* (per|a) (day|week|month)",
    r"earn (lakhs?|thousands?) (daily|weekly|monthly)",
    r"100% (placement|job|salary) guarantee",
    r"guaranteed (selection|offer|job)",
    r"selected without interview",
]

IMPERSONATION_SIGNALS = [
    "dear candidate", "dear applicant", "dear student",
    "we are pleased to inform you", "you have been shortlisted",
    "congratulations you have been selected",
    "offer letter attached", "joining letter",
]


def extract_sender_domain(text: str):
    match = re.search(r'from\s*:.*?<?([\w.+-]+@([\w.-]+))>?', text, re.IGNORECASE)
    if match:
        email = match.group(1)
        domain = match.group(2).lower()
        is_free = domain in FREE_EMAIL_DOMAINS
        return domain, is_free
    emails = re.findall(r'[\w.+-]+@([\w.-]+)', text)
    if emails:
        domain = emails[0].lower()
        return domain, domain in FREE_EMAIL_DOMAINS
    return None, False


def detect_urgency(text: str) -> list:
    found = []
    text_lower = text.lower()
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            found.append(pattern.replace(r'\d+', 'N').split(r'\b')[0])
    return found


def detect_fake_job_language(text: str) -> list:
    found = []
    text_lower = text.lower()
    for pattern in FAKE_JOB_PATTERNS:
        m = re.search(pattern, text_lower)
        if m:
            found.append(m.group(0)[:60])
    return found


def detect_impersonation(text: str) -> list:
    found = []
    text_lower = text.lower()
    for signal in IMPERSONATION_SIGNALS:
        if signal in text_lower:
            found.append(signal)
    return found


def generate_text_next_steps(score: int, flags: list, sender_domain: str | None, is_free_sender: bool) -> list:
    """Generate prioritized, actionable next-step recommendations for text/email analysis."""
    steps = []
    high_cats = {f["category"] for f in flags if f["severity"] == "high"}
    med_cats = {f["category"] for f in flags if f["severity"] == "medium"}
    all_risk_cats = high_cats | med_cats

    # Risk-level based main advice
    if score < 35:
        steps.append({
            "priority": "critical",
            "action": "Stop — do NOT respond to this message",
            "detail": "Multiple strong scam signals detected. Delete and block the sender immediately."
        })
        steps.append({
            "priority": "critical",
            "action": "Report the scam",
            "detail": "File a complaint at cybercrime.gov.in or call 1930 (India Cybercrime Helpline) to protect others."
        })
    elif score < 50:
        steps.append({
            "priority": "high",
            "action": "Do NOT share personal details or send any money",
            "detail": "High-risk content detected. Never provide Aadhaar, bank account details, or pay any kind of fee."
        })
        steps.append({
            "priority": "high",
            "action": "Verify the organization independently",
            "detail": "Search the company name on Google and LinkedIn. Contact them only via their official website — not the details in this message."
        })
    elif score < 65:
        steps.append({
            "priority": "medium",
            "action": "Cross-check before responding",
            "detail": "Look up the sender on Naukri, Internshala, or LinkedIn. Confirm the opportunity exists through their official channels."
        })

    # Sender domain check
    if is_free_sender and sender_domain:
        steps.append({
            "priority": "high",
            "action": "Be very wary of free email senders",
            "detail": f"Message from {sender_domain}. Genuine companies use official domain emails (@company.com). Free providers are a classic scam signal."
        })
    elif sender_domain and "Sender Domain" in all_risk_cats:
        steps.append({
            "priority": "medium",
            "action": "Verify the sender's email domain",
            "detail": f"Confirm {sender_domain} actually belongs to the organization by checking their official website."
        })

    # Scam keywords
    if "Scam Keywords" in high_cats:
        steps.append({
            "priority": "critical",
            "action": "Never pay any upfront fee",
            "detail": "Processing fees, security deposits, kit charges, and training fees are hallmarks of job/internship scams."
        })

    # Urgency detected
    if "Fake Urgency" in all_risk_cats:
        steps.append({
            "priority": "high",
            "action": "Ignore deadline pressure completely",
            "detail": "Real employers don't pressure you to act within hours. Artificial urgency is a manipulation tactic to prevent you from thinking clearly."
        })

    # Fake job claims
    if "Fake Opportunity Claims" in all_risk_cats:
        steps.append({
            "priority": "high",
            "action": "Reject inflated earning claims",
            "detail": "Guaranteed salaries, 100% placement, and 'no experience needed' are unrealistic promises used to lure victims."
        })

    # Impersonation
    if "Impersonation Signals" in all_risk_cats:
        steps.append({
            "priority": "high",
            "action": "Verify the offer through official HR channels",
            "detail": "Phrases like 'you have been selected' in unsolicited messages are classic impersonation tactics. Call the company directly to confirm."
        })

    # Domain age warnings
    if "Sender Domain Age" in all_risk_cats:
        steps.append({
            "priority": "high",
            "action": "Treat this new domain with extreme caution",
            "detail": "The sender's domain was registered very recently. Scam organizations frequently create fresh domains for each campaign."
        })

    # Safe score
    if score >= 75:
        steps.append({
            "priority": "low",
            "action": "Confirm via official channels anyway",
            "detail": "Even if this looks safe, always verify the opportunity through the company's official website or a trusted contact before proceeding."
        })

    return steps


def analyze_text(text: str, input_type: str = "text") -> dict:
    """Analyze pasted text (email body or social media post)."""
    text_lower = text.lower()
    flags = []
    all_keywords = []

    # 1. Scam keyword scan
    penalised = []
    skipped = []
    for word in HARD_SCAM_WORDS:
        if word in text_lower and word not in penalised:
            penalised.append(word)
    for word in CONTEXT_SENSITIVE_WORDS:
        if word in text_lower and word not in penalised and word not in skipped:
            idx = text_lower.find(word)
            if is_in_educational_context(text_lower, idx):
                skipped.append(word)
            else:
                penalised.append(word)

    # 2. Extract company name and domains/URLs
    import re
    from urllib.parse import urlparse
    
    sender_domain, is_free_sender = extract_sender_domain(text)
    urls = re.findall(r'(https?://[^\s]+)', text)
    
    domain_age_days = None
    target_domain = ""
    
    if sender_domain and not is_free_sender:
        target_domain = sender_domain
    elif urls:
        try:
            parsed_url = urlparse(urls[0])
            target_domain = parsed_url.hostname or ""
            target_domain = target_domain.lstrip("www.")
        except Exception:
            pass

    if target_domain:
        from analyzer import get_domain_age
        try:
            domain_age_days, _ = get_domain_age(target_domain)
        except Exception:
            pass

    # Extract company name
    company_name = "Unknown Employer"
    if sender_domain and not is_free_sender:
        company_name = sender_domain.split(".")[0].capitalize()
    else:
        match = re.search(r'(?:at|with|from|join|internship\s+in|job\s+at)\s+([A-Z][a-zA-Z0-9\s]{2,25})\b', text)
        if match:
            company_name = match.group(1).strip()
        else:
            if "@" in text:
                email_match = re.search(r'[\w\.-]+@([\w\.-]+)', text)
                if email_match:
                    company_name = email_match.group(1).split(".")[0].capitalize()

    # 3. Social Proof Check
    from analyzer import check_social_proof
    social_proof = check_social_proof(company_name, target_domain)

    # ──── Component-based Scoring ────

    # Component A: Domain Age Score (Max 20)
    domain_age_score = 20
    if target_domain:
        if domain_age_days is None:
            domain_age_score = 0
            flags.append({
                "category": "Domain Age",
                "severity": "high",
                "message": f"WHOIS data missing or hidden for domain '{target_domain}'. −20 points."
            })
        elif domain_age_days < 180:
            domain_age_score = 0
            flags.append({
                "category": "Domain Age",
                "severity": "high",
                "message": f"Domain '{target_domain}' is only {domain_age_days} days old. Freshly registered domains are a major scam signal. −20 points."
            })
        elif domain_age_days < 365:
            domain_age_score = 10
            flags.append({
                "category": "Domain Age",
                "severity": "medium",
                "message": f"Domain '{target_domain}' is {domain_age_days} days old (under 1 year). Proceed cautiously. −10 points."
            })
        else:
            flags.append({
                "category": "Domain Age",
                "severity": "low",
                "message": f"Domain '{target_domain}' is established ({domain_age_days} days old)."
            })
    else:
        domain_age_score = 10
        flags.append({
            "category": "Domain Age",
            "severity": "low",
            "message": "No domain name or link detected in text. Age score set to neutral (10/20)."
        })

    # Component B: Content Risk Score (Max 40)
    content_risk_score = 40
    
    if penalised:
        deduction = min(30, len(penalised) * 10)
        content_risk_score -= deduction
        flags.append({
            "category": "Scam Keywords",
            "severity": "high" if deduction >= 30 else "medium",
            "message": f"{len(penalised)} scam indicator(s) found: '{', '.join(penalised[:5])}'. −{deduction} points.",
        })
        all_keywords.extend(penalised)
    else:
        flags.append({
            "category": "Scam Keywords",
            "severity": "low",
            "message": "No obvious scam keywords found in the text.",
        })

    if skipped:
        flags.append({
            "category": "Scam Keywords",
            "severity": "low",
            "message": f"Words like '{', '.join(skipped[:3])}' were found in an educational context — no penalty.",
        })

    fake_job = detect_fake_job_language(text)
    if fake_job:
        content_risk_score -= 10
        flags.append({
            "category": "Fake Opportunity Claims",
            "severity": "high",
            "message": f"Unrealistic job/internship claims: '{fake_job[0]}'. −10 points.",
        })

    impersonation = detect_impersonation(text)
    if impersonation:
        content_risk_score -= 10
        flags.append({
            "category": "Impersonation Signals",
            "severity": "medium",
            "message": f"Phrases typical of fake HR emails: '{impersonation[0]}'. −10 points.",
        })

    content_risk_score = max(0, content_risk_score)

    # Component C: Social Proof Score (Max 20)
    social_proof_score = 10
    if social_proof["has_linkedin"]:
        social_proof_score += 10
        flags.append({
            "category": "Social Proof",
            "severity": "low",
            "message": f"LinkedIn Verifier: Found active profiles/presence for '{company_name}' ({social_proof['linkedin_count']} results). +10 points."
        })
    else:
        flags.append({
            "category": "Social Proof",
            "severity": "medium",
            "message": f"LinkedIn Verifier: Could not find any LinkedIn presence for '{company_name}'. Unverified employer. −0 points."
        })

    if social_proof["has_complaints"]:
        social_proof_score = max(0, social_proof_score - 15)
        flags.append({
            "category": "Social Proof Reputation",
            "severity": "high",
            "message": f"Alert: Potential negative discussions: {social_proof['messages'][0]} −15 points."
        })

    social_proof_score = max(0, min(20, social_proof_score))

    # Component D: Security / Authenticity Score (Max 20)
    security_authenticity_score = 20
    
    if input_type != "image" and sender_domain:
        if is_free_sender:
            security_authenticity_score -= 10
            flags.append({
                "category": "Sender Domain",
                "severity": "high",
                "message": f"Email sent from a free provider ({sender_domain}). Legitimate companies use corporate domain emails. −10 points.",
            })
        else:
            flags.append({
                "category": "Sender Domain",
                "severity": "low",
                "message": f"Email from a corporate domain ({sender_domain}).",
            })

    urgency = detect_urgency(text)
    if urgency:
        security_authenticity_score -= 10
        flags.append({
            "category": "Fake Urgency",
            "severity": "medium",
            "message": f"Pressure/urgency language detected ({len(urgency)} pattern(s)). −10 points.",
        })

    word_count = len(text.split())
    if word_count < 10:
        security_authenticity_score -= 5
        flags.append({
            "category": "Text Quality",
            "severity": "low",
            "message": f"Text is very short ({word_count} words). −5 points.",
        })

    security_authenticity_score = max(0, security_authenticity_score)

    # ──── Final score computation ────
    score = domain_age_score + content_risk_score + social_proof_score + security_authenticity_score
    score = max(0, min(100, score))

    if score >= 85:   grade = "A+"
    elif score >= 75: grade = "A"
    elif score >= 65: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 35: grade = "D"
    else:             grade = "F"

    if score < 50:
        summary = f"HIGH RISK — Trust score {score}/100. This text shows strong signs of a scam. Do not respond or share personal information."
    elif score < 65:
        summary = f"Suspicious content detected — Trust score {score}/100. Verify this opportunity independently before responding."
    elif score < 80:
        summary = f"Some warning signs present — Trust score {score}/100. Proceed with caution."
    else:
        summary = f"Text appears relatively safe — Trust score {score}/100. Always verify through official channels."

    next_steps = generate_text_next_steps(score, flags, sender_domain, is_free_sender)

    breakdown = {
        "domainAgeScore": domain_age_score,
        "domainAgeMax": 20,
        "contentRiskScore": content_risk_score,
        "contentRiskMax": 40,
        "socialProofScore": social_proof_score,
        "socialProofMax": 20,
        "securityOrAuthenticityScore": security_authenticity_score,
        "securityOrAuthenticityMax": 20,
    }

    return {
        "trustScore": score,
        "grade": grade,
        "flags": flags,
        "scamKeywordsFound": all_keywords,
        "summary": summary,
        "inputType": input_type,
        "nextSteps": next_steps,
        "breakdown": breakdown,
    }


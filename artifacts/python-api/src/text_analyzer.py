"""
Text / Email analysis module.
Accepts raw pasted text (email body, social media post, job ad).
"""
import re
from analyzer import HARD_SCAM_WORDS, CONTEXT_SENSITIVE_WORDS, EDUCATIONAL_CONTEXT_WORDS, is_in_educational_context

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


def extract_sender_domain(text: str) -> tuple[str | None, bool]:
    """Extract email sender domain and check if it's a free provider."""
    match = re.search(r'from\s*:.*?<?([\w.+-]+@([\w.-]+))>?', text, re.IGNORECASE)
    if match:
        email = match.group(1)
        domain = match.group(2).lower()
        is_free = domain in FREE_EMAIL_DOMAINS
        return domain, is_free
    # Also look for bare email addresses
    emails = re.findall(r'[\w.+-]+@([\w.-]+)', text)
    if emails:
        domain = emails[0].lower()
        return domain, domain in FREE_EMAIL_DOMAINS
    return None, False


def detect_urgency(text: str) -> list[str]:
    found = []
    text_lower = text.lower()
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            found.append(pattern.replace(r'\d+', 'N').replace(r'.{0,\d+}', '...').split(r'\b')[0])
    return found


def detect_fake_job_language(text: str) -> list[str]:
    found = []
    text_lower = text.lower()
    for pattern in FAKE_JOB_PATTERNS:
        m = re.search(pattern, text_lower)
        if m:
            found.append(m.group(0)[:60])
    return found


def detect_impersonation(text: str) -> list[str]:
    found = []
    text_lower = text.lower()
    for signal in IMPERSONATION_SIGNALS:
        if signal in text_lower:
            found.append(signal)
    return found


def analyze_text(text: str, input_type: str = "text") -> dict:
    """
    Analyze pasted text (email body or social media post).
    input_type: 'email' | 'text'
    """
    text_lower = text.lower()
    score = 100
    flags = []
    all_keywords = []

    # Scam keyword scan (same logic as URL analysis)
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

    if penalised:
        deduction = min(50, len(penalised) * 10)
        score -= deduction
        flags.append({
            "category": "Scam Keywords",
            "severity": "high" if deduction >= 30 else "medium",
            "message": f"{len(penalised)} scam indicator(s): '{', '.join(penalised[:5])}'. −{deduction} points.",
        })
        all_keywords.extend(penalised)
    else:
        flags.append({
            "category": "Scam Keywords",
            "severity": "low",
            "message": "No obvious scam keywords found in the text.",
        })

    # Email sender domain check
    if input_type == "email" or "@" in text:
        sender_domain, is_free = extract_sender_domain(text)
        if sender_domain:
            if is_free:
                score -= 20
                flags.append({
                    "category": "Sender Domain",
                    "severity": "high",
                    "message": f"Email sent from a free provider ({sender_domain}). Legitimate companies use corporate emails. −20 points.",
                })
            else:
                flags.append({
                    "category": "Sender Domain",
                    "severity": "low",
                    "message": f"Email sent from a non-free domain ({sender_domain}). Appears to be a corporate sender.",
                })

    # Urgency language
    urgency = detect_urgency(text)
    if urgency:
        score -= min(20, len(urgency) * 8)
        flags.append({
            "category": "Fake Urgency",
            "severity": "medium",
            "message": f"Pressure/urgency language detected ({len(urgency)} pattern(s)). Classic scam pressure tactic. −{min(20, len(urgency) * 8)} points.",
        })

    # Fake job/internship claims
    fake_job = detect_fake_job_language(text)
    if fake_job:
        score -= min(30, len(fake_job) * 15)
        flags.append({
            "category": "Fake Opportunity Claims",
            "severity": "high",
            "message": f"Unrealistic job/internship claims: '{fake_job[0]}'. −{min(30, len(fake_job) * 15)} points.",
        })

    # Impersonation signals
    impersonation = detect_impersonation(text)
    if impersonation:
        score -= 15
        flags.append({
            "category": "Impersonation Signals",
            "severity": "medium",
            "message": f"Phrases typical of fake HR emails: '{impersonation[0]}'. Proceed with caution. −15 points.",
        })

    # Word count sanity
    word_count = len(text.split())
    if word_count < 10:
        flags.append({
            "category": "Text Quality",
            "severity": "low",
            "message": f"Text is very short ({word_count} words). Analysis may be incomplete.",
        })

    score = max(0, min(100, score))

    if score >= 85:   grade = "A+"
    elif score >= 75: grade = "A"
    elif score >= 65: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 35: grade = "D"
    else:             grade = "F"

    if score < 50:
        summary = f"⚠️ HIGH RISK — Trust score {score}/100. This text shows strong signs of a scam. Do not respond or share personal information."
    elif score < 65:
        summary = f"Suspicious content detected. Trust score: {score}/100. Verify this opportunity independently."
    elif score < 80:
        summary = f"Some warning signs present. Trust score: {score}/100. Proceed with caution."
    else:
        summary = f"Text appears relatively safe. Trust score: {score}/100."

    return {
        "trustScore": score,
        "grade": grade,
        "flags": flags,
        "scamKeywordsFound": all_keywords,
        "summary": summary,
        "inputType": input_type,
    }

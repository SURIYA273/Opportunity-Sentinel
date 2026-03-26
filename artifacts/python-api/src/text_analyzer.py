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
    score = 100
    flags = []
    all_keywords = []

    # Scam keyword scan
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
            "message": f"{len(penalised)} scam indicator(s) found: '{', '.join(penalised[:5])}'. −{deduction} points.",
        })
        all_keywords.extend(penalised)
    else:
        flags.append({
            "category": "Scam Keywords",
            "severity": "low",
            "message": "No obvious scam keywords found in the text.",
        })

    # Email sender domain check
    sender_domain = None
    is_free_sender = False
    if input_type in ("email", "image") or "@" in text:
        sender_domain, is_free_sender = extract_sender_domain(text)
        if sender_domain:
            if is_free_sender:
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
                    "message": f"Email from a non-free domain ({sender_domain}). Appears to be a corporate sender.",
                })

            # ── Domain Age Check on sender domain ─────────────────────────────
            try:
                age_days, age_msg = get_domain_age(sender_domain)
                if age_days is None:
                    score -= 15
                    flags.append({
                        "category": "Sender Domain Age",
                        "severity": "high",
                        "message": f"Cannot verify registration age of '{sender_domain}'. Scam domains often hide WHOIS data. −15 points.",
                    })
                elif age_days < 180:
                    score -= 20
                    flags.append({
                        "category": "Sender Domain Age",
                        "severity": "high",
                        "message": f"Sender domain '{sender_domain}' is only {age_days} day(s) old — under 6 months. Freshly registered domains are a major scam red flag. −20 points.",
                    })
                elif age_days < 365:
                    score -= 10
                    flags.append({
                        "category": "Sender Domain Age",
                        "severity": "medium",
                        "message": f"Sender domain '{sender_domain}' is {age_days} days old (under 1 year). Proceed cautiously. −10 points.",
                    })
                else:
                    flags.append({
                        "category": "Sender Domain Age",
                        "severity": "low",
                        "message": f"Sender domain '{sender_domain}' has been registered for {age_days} days ({age_days // 365} year(s)). Established age is a positive signal.",
                    })
            except Exception:
                flags.append({
                    "category": "Sender Domain Age",
                    "severity": "low",
                    "message": f"Could not check domain age for '{sender_domain}'. Verify manually if needed.",
                })
        else:
            flags.append({
                "category": "Sender Domain Age",
                "severity": "low",
                "message": "No email address detected in the text — domain age check not applicable.",
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

    # Word count
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
        summary = f"HIGH RISK — Trust score {score}/100. This text shows strong signs of a scam. Do not respond or share personal information."
    elif score < 65:
        summary = f"Suspicious content detected — Trust score {score}/100. Verify this opportunity independently before responding."
    elif score < 80:
        summary = f"Some warning signs present — Trust score {score}/100. Proceed with caution."
    else:
        summary = f"Text appears relatively safe — Trust score {score}/100. Always verify through official channels."

    next_steps = generate_text_next_steps(score, flags, sender_domain, is_free_sender)

    return {
        "trustScore": score,
        "grade": grade,
        "flags": flags,
        "scamKeywordsFound": all_keywords,
        "summary": summary,
        "inputType": input_type,
        "nextSteps": next_steps,
    }

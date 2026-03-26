"""
Image OCR analysis module - Enhanced with:
- Multi-mode Tesseract OCR + image preprocessing for maximum text extraction
- Rich entity extraction (phones, URLs, emails, money amounts)
- Deeper scam scoring based on visual evidence
- Actionable next-steps recommendations based on score and findings
"""
import base64
import io
import re
from PIL import Image, ImageFilter, ImageEnhance
import pytesseract
from text_analyzer import analyze_text


# ─── Image Preprocessing ──────────────────────────────────────────────────────

def preprocess_image(image: Image.Image) -> list:
    """Generate multiple preprocessed variants to maximize OCR accuracy."""
    variants = []

    # 1. Original converted to RGB
    rgb = image.convert("RGB")
    variants.append(rgb)

    # 2. Grayscale + enhanced contrast
    gray = image.convert("L")
    enhanced = ImageEnhance.Contrast(gray).enhance(2.5)
    variants.append(enhanced)

    # 3. Grayscale + sharpened
    sharpened = gray.filter(ImageFilter.SHARPEN)
    variants.append(sharpened)

    # 4. High contrast + sharpen combined
    sharp_enhanced = ImageEnhance.Contrast(sharpened).enhance(2.0)
    variants.append(sharp_enhanced)

    # 5. Scaled up 2x (helps with small text)
    try:
        w, h = image.size
        big = gray.resize((w * 2, h * 2), Image.LANCZOS)
        variants.append(ImageEnhance.Contrast(big).enhance(2.0))
    except Exception:
        pass

    return variants


def run_ocr_multi_mode(image: Image.Image) -> str:
    """Run Tesseract with multiple PSM modes and return the longest result."""
    psm_modes = [
        "--psm 3",   # Fully automatic page segmentation (best general purpose)
        "--psm 6",   # Single uniform block of text
        "--psm 11",  # Sparse text — finds as much text as possible
        "--psm 4",   # Single column of text of variable sizes
        "--psm 12",  # Sparse text with OSD
    ]
    best_text = ""
    for psm in psm_modes:
        try:
            text = pytesseract.image_to_string(image, config=psm + " --oem 3")
            text = text.strip()
            if len(text) > len(best_text):
                best_text = text
        except Exception:
            continue
    return best_text


def extract_text_best(image: Image.Image) -> str:
    """Try all preprocessing variants + all PSM modes and return the best text."""
    variants = preprocess_image(image)
    best_text = ""
    for variant in variants:
        text = run_ocr_multi_mode(variant)
        if len(text) > len(best_text):
            best_text = text
    return best_text.strip()


# ─── Entity Extraction ────────────────────────────────────────────────────────

FREE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "rediffmail.com", "ymail.com", "aol.com", "mail.com",
    "protonmail.com", "icloud.com", "live.com", "zoho.com",
]


def extract_phone_numbers(text: str) -> list:
    patterns = [
        r'\+91[\s\-]?\d{5}[\s\-]?\d{5}',
        r'\b[6-9]\d{9}\b',
        r'\b\d{3}[\s\-]\d{3}[\s\-]\d{4}\b',
        r'\(\d{3}\)\s*\d{3}[\s\-]\d{4}',
        r'\+\d{1,3}[\s\-]\d{6,12}',
    ]
    found = []
    for p in patterns:
        found.extend(m.strip() for m in re.findall(p, text))
    return list(set(found))


def extract_urls(text: str) -> list:
    pattern = r'(?:https?://|www\.)\S+'
    found = re.findall(pattern, text, re.IGNORECASE)
    return [u.rstrip(".,;)\"'") for u in found]


def extract_emails(text: str) -> list:
    pattern = r'[\w.+-]+@[\w.-]+\.\w{2,}'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))


def extract_money_amounts(text: str) -> list:
    patterns = [
        r'(?:rs\.?|inr|₹)\s*[\d,]+(?:\.\d{1,2})?',
        r'\$\s*[\d,]+(?:\.\d{1,2})?',
        r'[\d,]+\s*(?:rupees?|lakhs?|thousands?)',
        r'(?:pay|payment|fee|deposit|charge)\s*(?:of\s*)?(?:rs\.?|₹|inr|\$)?\s*[\d,]+',
    ]
    found = []
    for p in patterns:
        found.extend(m.strip() for m in re.findall(p, text, re.IGNORECASE))
    return list(set(found))


def extract_organization_names(text: str) -> list:
    """Try to extract organization/company names mentioned in the image."""
    patterns = [
        r'(?:company|organization|org|firm|pvt\.?\s*ltd\.?|limited|inc\.?|llp)\b[^:\n]{0,40}',
        r'(?:from|by|at)\s+([A-Z][A-Za-z\s&.]{3,40}(?:Pvt|Ltd|Inc|Corp|Technologies|Solutions|Services|Institute|Academy|University|College)\b)',
    ]
    found = []
    for p in patterns:
        found.extend(re.findall(p, text, re.IGNORECASE)[:2])
    return list(set(f.strip() for f in found if len(f.strip()) > 4))


# ─── Next Steps Generator ─────────────────────────────────────────────────────

def generate_next_steps(score: int, flags: list, entities: dict) -> list:
    """Generate prioritized, actionable recommendations based on analysis."""
    steps = []
    high_cats = {f["category"] for f in flags if f["severity"] == "high"}
    med_cats = {f["category"] for f in flags if f["severity"] == "medium"}
    all_risk_cats = high_cats | med_cats

    # Critical: score very low
    if score < 35:
        steps.append({
            "priority": "critical",
            "action": "Stop — do NOT engage with this opportunity",
            "detail": "This image contains multiple strong scam indicators. Ignore, block, and delete this message."
        })
        steps.append({
            "priority": "critical",
            "action": "Report the scam immediately",
            "detail": "File a complaint at cybercrime.gov.in or call the India Cybercrime Helpline: 1930. This protects others too."
        })

    elif score < 50:
        steps.append({
            "priority": "high",
            "action": "Do NOT share personal details or money",
            "detail": "High-risk signals detected. Never provide Aadhaar, bank details, or pay any kind of fee to this sender."
        })
        steps.append({
            "priority": "high",
            "action": "Verify the organization independently",
            "detail": "Search the company name on Google and LinkedIn. Contact them only via their officially published website or phone — not the details in this image."
        })

    elif score < 65:
        steps.append({
            "priority": "medium",
            "action": "Cross-check before responding",
            "detail": "Look up the sender on Naukri, Internshala, or LinkedIn. Confirm the opportunity exists on their official channels."
        })

    # Fee / payment mentioned
    if entities.get("money") or "Fee / Payment Detected" in all_risk_cats:
        steps.append({
            "priority": "critical",
            "action": "Refuse any payment request",
            "detail": "Legitimate internships and jobs never charge application, training, kit, or security deposit fees. Any such demand is a scam red flag."
        })

    # Urgency or fake claims
    if "Fake Urgency" in all_risk_cats or "Fake Opportunity Claims" in all_risk_cats:
        steps.append({
            "priority": "high",
            "action": "Ignore pressure and exaggerated promises",
            "detail": "Real employers don't set 24-hour deadlines or guarantee salaries of lakhs. Urgency is designed to make you act before thinking."
        })

    # Scam keywords
    if "Scam Keywords" in high_cats:
        steps.append({
            "priority": "high",
            "action": "Never pay upfront fees",
            "detail": "Processing fees, security deposits, and training charges are classic scam tactics. No genuine offer requires this."
        })

    # Phone numbers found
    if entities.get("phones"):
        steps.append({
            "priority": "medium",
            "action": "Verify phone numbers before calling",
            "detail": f"Number(s) found: {', '.join(entities['phones'][:3])}. Search on Truecaller or the company's official site to confirm legitimacy."
        })

    # Suspicious emails
    if entities.get("emails"):
        suspicious = [e for e in entities["emails"] if any(e.lower().endswith("@" + d) for d in FREE_EMAIL_DOMAINS)]
        if suspicious:
            steps.append({
                "priority": "high",
                "action": "Be wary of free email addresses",
                "detail": f"Free email(s) found: {', '.join(suspicious[:2])}. Genuine companies always use official domain emails (@company.com), not Gmail or Yahoo."
            })
        else:
            steps.append({
                "priority": "low",
                "action": "Confirm the email domain",
                "detail": f"Email(s) detected: {', '.join(entities['emails'][:2])}. Make sure the domain matches the company's official website."
            })

    # URLs found
    if entities.get("urls"):
        steps.append({
            "priority": "medium",
            "action": "Check all links before clicking",
            "detail": f"URL(s) in image: {', '.join(entities['urls'][:2])}. Paste each into the URL Checker tab in this tool to verify them first."
        })

    # Safe score — still advise caution
    if score >= 75:
        steps.append({
            "priority": "low",
            "action": "Confirm via official channels anyway",
            "detail": "The image appears relatively safe, but always verify the opportunity directly on the company's official website or through a known contact."
        })

    return steps


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def analyze_image(image_base64: str) -> dict:
    """
    Full-pipeline image analysis:
    1. Multi-mode OCR with preprocessing
    2. Entity extraction (phones, emails, URLs, money)
    3. Scam text analysis with additional entity-based scoring
    4. Actionable next steps
    """
    try:
        # Decode base64
        if "," in image_base64:
            image_base64 = image_base64.split(",", 1)[1]
        image_bytes = base64.b64decode(image_base64)
        image = Image.open(io.BytesIO(image_bytes))

        # Enhanced multi-mode OCR
        extracted_text = extract_text_best(image)

        if not extracted_text or len(extracted_text.split()) < 3:
            return {
                "trustScore": 50,
                "grade": "C",
                "flags": [{
                    "category": "OCR Extraction",
                    "severity": "medium",
                    "message": "Could not extract readable text. Try a clearer, higher-resolution screenshot with visible text.",
                }],
                "scamKeywordsFound": [],
                "summary": "No text could be extracted. The image may be too blurry, low-resolution, or contain only graphics.",
                "inputType": "image",
                "extractedText": "",
                "entities": {},
                "nextSteps": [{
                    "priority": "medium",
                    "action": "Upload a clearer image",
                    "detail": "Ensure the screenshot is sharp and text is legible. Zoom into the relevant section before capturing."
                }],
            }

        # Entity extraction
        phones = extract_phone_numbers(extracted_text)
        urls = extract_urls(extracted_text)
        emails = extract_emails(extracted_text)
        money = extract_money_amounts(extracted_text)
        entities = {"phones": phones, "urls": urls, "emails": emails, "money": money}

        # Core scam text analysis
        result = analyze_text(extracted_text, input_type="image")

        # Insert OCR success flag at the top
        word_count = len(extracted_text.split())
        result["flags"].insert(0, {
            "category": "OCR Extraction",
            "severity": "low",
            "message": f"Successfully extracted {word_count} word(s) from the image using enhanced multi-mode OCR.",
        })

        # --- Additional entity-based scoring ---
        score = result["trustScore"]

        # Money amounts in image → high risk
        if money:
            score = max(0, score - 20)
            result["flags"].insert(1, {
                "category": "Fee / Payment Detected",
                "severity": "high",
                "message": f"Money amount(s) detected in image: {', '.join(money[:4])}. Legitimate opportunities never demand upfront payments. −20 points.",
            })

        # Free email domains in image → high risk
        if emails:
            suspicious_emails = [e for e in emails if any(e.lower().endswith("@" + d) for d in FREE_EMAIL_DOMAINS)]
            if suspicious_emails:
                score = max(0, score - 15)
                result["flags"].append({
                    "category": "Free Email in Image",
                    "severity": "high",
                    "message": f"Free-provider email(s) found: {', '.join(suspicious_emails[:2])}. Real companies use official domain emails. −15 points.",
                })
            else:
                result["flags"].append({
                    "category": "Email Detected",
                    "severity": "low",
                    "message": f"Email(s) found: {', '.join(emails[:3])}. Verify the domain matches the company's official site.",
                })

        # Phone numbers — informational
        if phones:
            result["flags"].append({
                "category": "Phone Numbers Detected",
                "severity": "low",
                "message": f"Phone number(s) extracted: {', '.join(phones[:3])}. Verify on Truecaller or official company directories before calling.",
            })

        # URLs — prompt to use URL checker
        if urls:
            result["flags"].append({
                "category": "Links Detected",
                "severity": "medium",
                "message": f"URL(s) found in image: {', '.join(urls[:2])}. Use the URL Checker tab to verify before visiting.",
            })

        # Clamp and re-grade
        score = max(0, min(100, score))
        result["trustScore"] = score

        if score >= 85:   result["grade"] = "A+"
        elif score >= 75: result["grade"] = "A"
        elif score >= 65: result["grade"] = "B"
        elif score >= 50: result["grade"] = "C"
        elif score >= 35: result["grade"] = "D"
        else:             result["grade"] = "F"

        # Recalculate summary
        if score < 50:
            result["summary"] = (
                f"HIGH RISK — Trust score {score}/100. "
                "Multiple red flags detected in this image. Do NOT engage, share details, or pay anything."
            )
        elif score < 65:
            result["summary"] = (
                f"Suspicious content — Trust score {score}/100. "
                "Verify this independently through official channels before responding."
            )
        elif score < 80:
            result["summary"] = (
                f"Some warning signs present — Trust score {score}/100. "
                "Proceed with caution and double-check through official sources."
            )
        else:
            result["summary"] = (
                f"Image content appears relatively safe — Trust score {score}/100. "
                "Always confirm through official channels."
            )

        # Generate next steps
        next_steps = generate_next_steps(score, result["flags"], entities)

        result["extractedText"] = extracted_text
        result["inputType"] = "image"
        result["entities"] = entities
        result["nextSteps"] = next_steps

        return result

    except Exception as e:
        return {
            "trustScore": 50,
            "grade": "C",
            "flags": [{
                "category": "OCR",
                "severity": "medium",
                "message": f"Image processing error: {str(e)[:150]}. Ensure the file is a valid PNG/JPG.",
            }],
            "scamKeywordsFound": [],
            "summary": "Could not process the image.",
            "inputType": "image",
            "extractedText": "",
            "entities": {},
            "nextSteps": [],
        }

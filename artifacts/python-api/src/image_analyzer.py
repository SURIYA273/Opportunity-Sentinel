"""
Image OCR analysis module — optimized for speed and accuracy.
Uses 2 preprocessing variants × 2 Tesseract PSM modes (4 passes total)
with image resizing for fast, reliable text extraction.
"""
import base64
import io
import re
from PIL import Image, ImageEnhance, ImageFilter
import pytesseract
from text_analyzer import analyze_text


# ─── Constants ────────────────────────────────────────────────────────────────

MAX_OCR_WIDTH = 1400   # resize images wider than this before OCR
MAX_OCR_HEIGHT = 1400

FREE_EMAIL_DOMAINS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "rediffmail.com", "ymail.com", "aol.com", "mail.com",
    "protonmail.com", "icloud.com", "live.com", "zoho.com",
]


# ─── Image Preprocessing (fast — 2 variants only) ─────────────────────────────

def resize_for_ocr(image: Image.Image) -> Image.Image:
    """Resize image if too large — keeps OCR fast without losing quality."""
    w, h = image.size
    if w > MAX_OCR_WIDTH or h > MAX_OCR_HEIGHT:
        ratio = min(MAX_OCR_WIDTH / w, MAX_OCR_HEIGHT / h)
        new_size = (int(w * ratio), int(h * ratio))
        image = image.resize(new_size, Image.LANCZOS)
    return image


def preprocess_fast(image: Image.Image) -> list:
    """Return 2 quick preprocessing variants."""
    image = resize_for_ocr(image)
    gray = image.convert("L")
    # Variant 1: grayscale with boosted contrast
    enhanced = ImageEnhance.Contrast(gray).enhance(2.0)
    # Variant 2: grayscale + sharpen
    sharpened = gray.filter(ImageFilter.SHARPEN)
    return [enhanced, sharpened]


# ─── OCR (2 PSM modes — fast and general-purpose) ────────────────────────────

def extract_text_fast(image: Image.Image) -> str:
    """Run OCR on 2 preprocessed variants × 2 PSM modes. Return the best result."""
    psm_modes = ["--psm 3 --oem 3", "--psm 6 --oem 3"]
    variants = preprocess_fast(image)
    best = ""
    for variant in variants:
        for psm in psm_modes:
            try:
                text = pytesseract.image_to_string(variant, config=psm).strip()
                if len(text) > len(best):
                    best = text
            except Exception:
                continue
    return best


# ─── Entity Extraction ────────────────────────────────────────────────────────

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
    return list(set(found))[:5]


def extract_urls(text: str) -> list:
    pattern = r'(?:https?://|www\.)\S+'
    found = re.findall(pattern, text, re.IGNORECASE)
    return [u.rstrip(".,;)\"'") for u in found][:3]


def extract_emails(text: str) -> list:
    pattern = r'[\w.+-]+@[\w.-]+\.\w{2,}'
    return list(set(re.findall(pattern, text, re.IGNORECASE)))[:5]


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
    return list(set(found))[:4]


# ─── Next Steps Generator ─────────────────────────────────────────────────────

def generate_next_steps(score: int, flags: list, entities: dict) -> list:
    steps = []
    high_cats = {f["category"] for f in flags if f["severity"] == "high"}
    med_cats = {f["category"] for f in flags if f["severity"] == "medium"}
    all_risk_cats = high_cats | med_cats

    if score < 35:
        steps.append({
            "priority": "critical",
            "action": "Stop — do NOT engage with this opportunity",
            "detail": "Multiple strong scam indicators found. Delete, block, and ignore this immediately."
        })
        steps.append({
            "priority": "critical",
            "action": "Report the scam immediately",
            "detail": "File a complaint at cybercrime.gov.in or call the India Cybercrime Helpline: 1930."
        })
    elif score < 50:
        steps.append({
            "priority": "high",
            "action": "Do NOT share personal details or send money",
            "detail": "High-risk signals found. Never provide Aadhaar, bank details, or pay any kind of fee to this sender."
        })
        steps.append({
            "priority": "high",
            "action": "Verify the organization independently",
            "detail": "Search the company on Google and LinkedIn. Contact them only via their officially published website or phone — not the details in this image."
        })
    elif score < 65:
        steps.append({
            "priority": "medium",
            "action": "Cross-check before responding",
            "detail": "Look up the sender on Naukri, Internshala, or LinkedIn and confirm the opportunity through official channels."
        })

    if entities.get("money") or "Fee / Payment Detected" in all_risk_cats:
        steps.append({
            "priority": "critical",
            "action": "Refuse any payment request",
            "detail": "Legitimate internships and jobs NEVER charge application, training, kit, or security deposit fees. Any such demand is a scam."
        })

    if "Fake Urgency" in all_risk_cats or "Fake Opportunity Claims" in all_risk_cats:
        steps.append({
            "priority": "high",
            "action": "Ignore pressure and exaggerated promises",
            "detail": "Real employers don't set 24-hour deadlines or guarantee lakhs of salary. Urgency prevents you from thinking clearly."
        })

    if "Scam Keywords" in high_cats:
        steps.append({
            "priority": "high",
            "action": "Never pay any upfront fee",
            "detail": "Processing fees, deposits, and training charges are classic scam tactics. No genuine offer requires this."
        })

    if entities.get("phones"):
        steps.append({
            "priority": "medium",
            "action": "Verify phone numbers before calling",
            "detail": f"Number(s) found: {', '.join(entities['phones'][:3])}. Check on Truecaller or the company's official site first."
        })

    if entities.get("emails"):
        suspicious = [e for e in entities["emails"] if any(e.lower().endswith("@" + d) for d in FREE_EMAIL_DOMAINS)]
        if suspicious:
            steps.append({
                "priority": "high",
                "action": "Be wary of free email addresses",
                "detail": f"Free email(s) found: {', '.join(suspicious[:2])}. Real companies use official domain emails (@company.com), not Gmail or Yahoo."
            })
        else:
            steps.append({
                "priority": "low",
                "action": "Confirm the email domain",
                "detail": f"Email(s) detected: {', '.join(entities['emails'][:2])}. Verify it matches the company's official website."
            })

    if entities.get("urls"):
        steps.append({
            "priority": "medium",
            "action": "Check all links before clicking",
            "detail": f"URL(s) in image: {', '.join(entities['urls'][:2])}. Paste into the URL Checker tab in this tool to verify first."
        })

    if score >= 75:
        steps.append({
            "priority": "low",
            "action": "Still confirm through official channels",
            "detail": "Even if content looks safe, always verify the opportunity directly on the company's official website or through a known contact."
        })

    return steps


# ─── Main Entry Point ─────────────────────────────────────────────────────────

def analyze_image(image_base64: str) -> dict:
    """
    Fast image analysis pipeline:
    1. Resize + 2-variant OCR (4 total passes)
    2. Entity extraction (phones, emails, URLs, money)
    3. Scam text analysis + entity scoring
    4. Actionable next steps
    """
    try:
        # Decode
        if "," in image_base64:
            image_base64 = image_base64.split(",", 1)[1]
        image_bytes = base64.b64decode(image_base64)
        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")

        # OCR
        extracted_text = extract_text_fast(image)

        if not extracted_text or len(extracted_text.split()) < 3:
            return {
                "trustScore": 50,
                "grade": "C",
                "flags": [{
                    "category": "OCR Extraction",
                    "severity": "medium",
                    "message": "Could not extract readable text. Upload a clearer, sharper screenshot with visible text.",
                }],
                "scamKeywordsFound": [],
                "summary": "No text could be extracted. The image may be blurry, low-resolution, or contain only graphics.",
                "inputType": "image",
                "extractedText": "",
                "entities": {},
                "nextSteps": [{
                    "priority": "medium",
                    "action": "Upload a clearer image",
                    "detail": "Make sure the screenshot is sharp and text is visible. Zoom into the relevant section before capturing."
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

        word_count = len(extracted_text.split())
        result["flags"].insert(0, {
            "category": "OCR Extraction",
            "severity": "low",
            "message": f"Successfully extracted {word_count} word(s) from the image using enhanced OCR.",
        })

        score = result["trustScore"]

        # Money amounts → high risk penalty
        if money:
            score = max(0, score - 20)
            result["flags"].insert(1, {
                "category": "Fee / Payment Detected",
                "severity": "high",
                "message": f"Payment/fee amount(s) found: {', '.join(money[:3])}. Legitimate opportunities never require upfront fees. −20 points.",
            })

        # Free email providers → penalty
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
                "message": f"Phone number(s) extracted: {', '.join(phones[:3])}. Verify on Truecaller or official directories before calling.",
            })

        # URLs — informational
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

        if score < 50:
            result["summary"] = f"HIGH RISK — Trust score {score}/100. Multiple red flags detected. Do NOT engage, share personal details, or pay anything."
        elif score < 65:
            result["summary"] = f"Suspicious content — Trust score {score}/100. Verify independently before responding."
        elif score < 80:
            result["summary"] = f"Some warning signs present — Trust score {score}/100. Proceed with caution and verify through official sources."
        else:
            result["summary"] = f"Image content appears relatively safe — Trust score {score}/100. Still confirm through official channels."

        result["extractedText"] = extracted_text
        result["inputType"] = "image"
        result["entities"] = entities
        result["nextSteps"] = generate_next_steps(score, result["flags"], entities)

        return result

    except Exception as e:
        return {
            "trustScore": 50,
            "grade": "C",
            "flags": [{
                "category": "Processing Error",
                "severity": "medium",
                "message": f"Image processing error: {str(e)[:150]}. Ensure the file is a valid PNG or JPG.",
            }],
            "scamKeywordsFound": [],
            "summary": "Could not process the image.",
            "inputType": "image",
            "extractedText": "",
            "entities": {},
            "nextSteps": [],
        }

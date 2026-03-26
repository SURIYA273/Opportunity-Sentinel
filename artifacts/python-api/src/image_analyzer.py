"""
Image OCR analysis module.
Accepts a base64-encoded image, extracts text via pytesseract, 
then runs the same scam text analysis.
"""
import base64
import io
from PIL import Image
import pytesseract
from text_analyzer import analyze_text


def analyze_image(image_base64: str) -> dict:
    """
    Extract text from a base64-encoded image and run scam text analysis.
    """
    try:
        # Decode base64
        if "," in image_base64:
            image_base64 = image_base64.split(",", 1)[1]
        image_bytes = base64.b64decode(image_base64)
        image = Image.open(io.BytesIO(image_bytes))

        # OCR
        extracted_text = pytesseract.image_to_string(image, config="--psm 6")
        extracted_text = extracted_text.strip()

        if not extracted_text:
            return {
                "trustScore": 50,
                "grade": "C",
                "flags": [{
                    "category": "OCR",
                    "severity": "medium",
                    "message": "Could not extract any readable text from the image. Try a clearer screenshot.",
                }],
                "scamKeywordsFound": [],
                "summary": "No text could be extracted from the image.",
                "inputType": "image",
                "extractedText": "",
            }

        result = analyze_text(extracted_text, input_type="image")
        result["extractedText"] = extracted_text
        result["inputType"] = "image"

        # Add an OCR success flag
        result["flags"].insert(0, {
            "category": "OCR",
            "severity": "low",
            "message": f"Successfully extracted {len(extracted_text.split())} word(s) from the image.",
        })

        return result

    except Exception as e:
        return {
            "trustScore": 50,
            "grade": "C",
            "flags": [{
                "category": "OCR",
                "severity": "medium",
                "message": f"Image processing error: {str(e)[:120]}. Ensure the image is a valid PNG/JPG.",
            }],
            "scamKeywordsFound": [],
            "summary": "Could not process the image.",
            "inputType": "image",
            "extractedText": "",
        }

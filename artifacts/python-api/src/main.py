import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

from analyzer import analyze_url
from text_analyzer import analyze_text
from image_analyzer import analyze_image

app = FastAPI(title="Student Opportunity Verifier API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request / Response Models ────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str

class AnalyzeTextRequest(BaseModel):
    text: str
    inputType: str = "text"   # "email" | "text" | "image"

class AnalyzeImageRequest(BaseModel):
    imageBase64: str          # data URI or raw base64


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/api/healthz")
async def health_check():
    return {"status": "ok"}


@app.post("/api/analyze")
async def analyze_url_endpoint(request: AnalyzeRequest):
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL is required")
    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        return analyze_url(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/text")
async def analyze_text_endpoint(request: AnalyzeTextRequest):
    if not request.text or not request.text.strip():
        raise HTTPException(status_code=400, detail="Text is required")
    try:
        return analyze_text(request.text.strip(), input_type=request.inputType)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analyze/image")
async def analyze_image_endpoint(request: AnalyzeImageRequest):
    if not request.imageBase64 or not request.imageBase64.strip():
        raise HTTPException(status_code=400, detail="imageBase64 is required")
    try:
        return analyze_image(request.imageBase64.strip())
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PYTHON_API_PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)

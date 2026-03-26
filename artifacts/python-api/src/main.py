import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional

from analyzer import analyze_url

app = FastAPI(title="Student Opportunity Verifier API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    url: str


class ScamFlag(BaseModel):
    category: str
    severity: str
    message: str


class AnalyzeResponse(BaseModel):
    url: str
    trustScore: float
    grade: str
    flags: list[ScamFlag]
    sslValid: bool
    domainAgeDays: Optional[float] = None
    domainExtension: str
    inputFieldCount: float
    scamKeywordsFound: list[str]
    summary: str


@app.get("/api/healthz")
async def health_check():
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(request: AnalyzeRequest):
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL is required")

    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        result = analyze_url(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PYTHON_API_PORT", 8001))
    uvicorn.run(app, host="0.0.0.0", port=port)

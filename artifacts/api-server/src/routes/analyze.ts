import { Router, type IRouter } from "express";
import { AnalyzeUrlBody, AnalyzeUrlResponse } from "@workspace/api-zod";

const router: IRouter = Router();

const PYTHON_API_URL = `http://localhost:${process.env.PYTHON_API_PORT || "8001"}`;

async function proxyToPython(
  req: import("express").Request,
  res: import("express").Response,
  path: string,
): Promise<void> {
  try {
    const response = await fetch(`${PYTHON_API_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req.body),
      signal: AbortSignal.timeout(90000),
    });

    const data = await response.json();

    if (!response.ok) {
      res.status(response.status).json({ error: "Analysis failed", detail: JSON.stringify(data) });
      return;
    }

    res.json(data);
  } catch (err: unknown) {
    req.log.error({ err }, "Failed to contact Python API");
    if (err instanceof Error && err.name === "TimeoutError") {
      res.status(504).json({ error: "Analysis timed out", detail: "The analysis took too long. Please try again." });
      return;
    }
    res.status(502).json({ error: "Analysis service unavailable", detail: "Could not reach the analysis backend." });
  }
}

router.post("/analyze", async (req, res): Promise<void> => {
  const parsed = AnalyzeUrlBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request body", detail: parsed.error.message });
    return;
  }
  await proxyToPython(req, res, "/api/analyze");
});

router.post("/analyze/text", async (req, res): Promise<void> => {
  if (!req.body?.text) {
    res.status(400).json({ error: "text field is required" });
    return;
  }
  await proxyToPython(req, res, "/api/analyze/text");
});

router.post("/analyze/image", async (req, res): Promise<void> => {
  if (!req.body?.imageBase64) {
    res.status(400).json({ error: "imageBase64 field is required" });
    return;
  }
  await proxyToPython(req, res, "/api/analyze/image");
});

export default router;

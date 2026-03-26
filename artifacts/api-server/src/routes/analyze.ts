import { Router, type IRouter } from "express";
import { AnalyzeUrlBody, AnalyzeUrlResponse } from "@workspace/api-zod";

const router: IRouter = Router();

const PYTHON_API_URL = `http://localhost:${process.env.PYTHON_API_PORT || "8001"}`;

router.post("/analyze", async (req, res): Promise<void> => {
  const parsed = AnalyzeUrlBody.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: "Invalid request body", detail: parsed.error.message });
    return;
  }

  try {
    const response = await fetch(`${PYTHON_API_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed.data),
      signal: AbortSignal.timeout(60000),
    });

    if (!response.ok) {
      const errorText = await response.text();
      req.log.warn({ status: response.status, error: errorText }, "Python API returned error");
      res.status(response.status).json({ error: "Analysis failed", detail: errorText });
      return;
    }

    const data = await response.json();
    const validated = AnalyzeUrlResponse.safeParse(data);
    if (!validated.success) {
      req.log.warn({ errors: validated.error.message }, "Python API response validation failed");
      res.json(data);
      return;
    }

    res.json(validated.data);
  } catch (err: unknown) {
    req.log.error({ err }, "Failed to contact Python API");
    if (err instanceof Error && err.name === "TimeoutError") {
      res.status(504).json({ error: "Analysis timed out", detail: "The URL analysis took too long. Please try again." });
      return;
    }
    res.status(502).json({ error: "Analysis service unavailable", detail: "Could not reach the analysis backend." });
  }
});

export default router;

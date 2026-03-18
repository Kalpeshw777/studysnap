const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "AIzaSyDy_VQFoHwqG8WAGpiiIxpaHMT-dSg2ZjQ";
const GEMINI_URL = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`;

app.post("/api/generate", async (req, res) => {
  const { topic, level, depth } = req.body;

  if (!topic) return res.status(400).json({ error: "Topic is required" });

  const numPoints = depth === "quick" ? 5 : depth === "deep" ? 15 : 10;

  const prompt = `You are an expert study assistant and educator. Generate accurate, detailed study notes for the topic: "${topic}" at ${level || "intermediate"} level.

You MUST respond with ONLY valid JSON — no markdown fences, no explanation, no extra text before or after.

Use this exact JSON structure:
{
  "definition": "A precise 2-3 sentence definition/overview of the topic",
  "points": [
    {"title": "Concept Name", "text": "Clear explanation. Wrap key terms in <strong>tags</strong>."}
  ],
  "formulas": ["formula or equation string, e.g. E = mc²"],
  "qa": [
    {"q": "A specific exam-style question?", "a": "A complete, accurate answer.", "diff": "easy"}
  ]
}

Rules:
- Include exactly ${numPoints} items in "points"
- Include exactly 5 items in "qa"
- diff must be one of: easy, medium, hard
- "formulas" should be an empty array [] if the topic has no formulas/equations
- All answers must be factually correct and detailed
- Use <strong> tags in point text to highlight key terms`;

  try {
    const response = await fetch(GEMINI_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.3, topP: 0.8, maxOutputTokens: 2048 }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(500).json({ error: data.error?.message || "Gemini API error" });
    }

    const raw = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
    const clean = raw.replace(/```json\s*/gi, "").replace(/```\s*/g, "").trim();
    const parsed = JSON.parse(clean);
    res.json(parsed);
  } catch (err) {
    console.error("Error:", err.message);
    res.status(500).json({ error: "Failed to generate notes. Please try again." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`StudySnap running on port ${PORT}`));

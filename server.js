const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const { MongoClient } = require("mongodb");
const { OAuth2Client } = require("google-auth-library");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const GROQ_API_KEY = process.env.GROQ_API_KEY;
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const MONGODB_URI = process.env.MONGODB_URI;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

let db;
MongoClient.connect(MONGODB_URI).then(client => {
  db = client.db("studysnap");
  console.log("MongoDB connected");
}).catch(err => console.error("MongoDB error:", err.message));

function createToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify({ ...payload, iat: Date.now() })).toString("base64url");
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url");
  return `${header}.${body}.${sig}`;
}

function verifyToken(token) {
  try {
    const [header, body, sig] = token.split(".");
    const expected = crypto.createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url");
    if (sig !== expected) return null;
    return JSON.parse(Buffer.from(body, "base64url").toString());
  } catch { return null; }
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: "Invalid token" });
  req.user = payload;
  next();
}

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

app.post("/api/auth/google", async (req, res) => {
  const { credential } = req.body;
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const { email, name, picture, sub: googleId } = ticket.getPayload();
    const users = db.collection("users");
    await users.updateOne(
      { email },
      { $set: { email, name, picture, googleId, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date(), supporter: false } },
      { upsert: true }
    );
    const user = await users.findOne({ email });
    const token = createToken({ email, name, picture });
    res.json({ token, user: { email, name, picture, supporter: user.supporter } });
  } catch (err) {
    console.error("Google auth error:", err.message);
    res.status(401).json({ error: "Invalid Google token" });
  }
});

app.get("/api/user/status", authMiddleware, async (req, res) => {
  try {
    const user = await db.collection("users").findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ email: user.email, name: user.name, picture: user.picture, supporter: user.supporter });
  } catch (err) {
    res.status(500).json({ error: "Failed to get user status" });
  }
});

app.post("/api/generate", authMiddleware, async (req, res) => {
  const { topic, level, depth } = req.body;
  if (!topic) return res.status(400).json({ error: "Topic is required" });

  await db.collection("users").updateOne(
    { email: req.user.email },
    { $inc: { totalGenerations: 1 }, $set: { lastUsed: new Date() } }
  );

  const numPoints = depth === "quick" ? 5 : depth === "deep" ? 15 : 10;
  const prompt = `You are an expert study assistant and educator. Generate accurate, detailed study notes for the topic: "${topic}" at ${level || "intermediate"} level.
You MUST respond with ONLY valid JSON — no markdown fences, no explanation, no extra text before or after.
Use this exact JSON structure:
{"definition":"2-3 sentence overview","points":[{"title":"Concept","text":"Explanation with <strong>key terms</strong>"}],"formulas":["formula if applicable"],"qa":[{"q":"Question?","a":"Answer.","diff":"easy"}]}
Rules: ${numPoints} points, 5 qa items, diff = easy/medium/hard, empty formulas array if none, use <strong> tags`;

  try {
    const response = await fetch(GROQ_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${GROQ_API_KEY}` },
      body: JSON.stringify({ model: "llama-3.3-70b-versatile", messages: [{ role: "user", content: prompt }], temperature: 0.3, max_tokens: 2048 })
    });

    const data = await response.json();

    if (!response.ok) {
      const errMsg = data.error?.message || "";
      if (errMsg.includes("rate_limit") || response.status === 429) {
        return res.status(429).json({ error: "⚡ StudySnap is experiencing high traffic! Please try again in a few minutes." });
      }
      return res.status(500).json({ error: errMsg || "Groq API error" });
    }

    const raw = data.choices?.[0]?.message?.content || "";
    const clean = raw.replace(/```json\s*/gi, "").replace(/```\s*/g, "").trim();
    res.json(JSON.parse(clean));
  } catch (err) {
    console.error("Error:", err.message);
    res.status(500).json({ error: "Failed to generate notes. Please try again." });
  }
});

app.post("/api/create-order", authMiddleware, async (req, res) => {
  const { amount } = req.body;
  const amountInPaise = (amount || 99) * 100;
  try {
    const response = await fetch("https://api.razorpay.com/v1/orders", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Basic " + Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString("base64") },
      body: JSON.stringify({ amount: amountInPaise, currency: "INR", receipt: `donation_${Date.now()}` })
    });
    const order = await response.json();
    if (!response.ok) return res.status(500).json({ error: order.error?.description || "Order creation failed" });
    res.json({ orderId: order.id, amount: amountInPaise, currency: "INR", keyId: RAZORPAY_KEY_ID });
  } catch (err) {
    res.status(500).json({ error: "Failed to create order" });
  }
});

app.post("/api/verify-payment", authMiddleware, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const expectedSignature = crypto.createHmac("sha256", RAZORPAY_KEY_SECRET).update(razorpay_order_id + "|" + razorpay_payment_id).digest("hex");
  if (expectedSignature !== razorpay_signature) {
    return res.status(400).json({ success: false, error: "Verification failed" });
  }
  await db.collection("users").updateOne(
    { email: req.user.email },
    { $set: { supporter: true, supportedAt: new Date(), lastPaymentId: razorpay_payment_id } }
  );
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`StudySnap running on port ${PORT}`));

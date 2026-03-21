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

// ── GOOGLE AUTH ───────────────────────────────────────────────────────────────
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

// ── USER STATUS ───────────────────────────────────────────────────────────────
app.get("/api/user/status", authMiddleware, async (req, res) => {
  try {
    const user = await db.collection("users").findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ email: user.email, name: user.name, picture: user.picture, supporter: user.supporter });
  } catch (err) {
    res.status(500).json({ error: "Failed to get user status" });
  }
});

// ── GENERATE NOTES ────────────────────────────────────────────────────────────
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
Rules: ${numPoints} points, EXACTLY 10 qa items, diff = easy/medium/hard mix, empty formulas array if none, use <strong> tags in points text only`;

  try {
    const response = await fetch(GROQ_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${GROQ_API_KEY}` },
      body: JSON.stringify({ model: "llama-3.3-70b-versatile", messages: [{ role: "user", content: prompt }], temperature: 0.3, max_tokens: 2048 })
    });
    const data = await response.json();
    if (!response.ok) return res.status(500).json({ error: data.error?.message || "Groq API error" });
    const raw = data.choices?.[0]?.message?.content || "";
    const clean = raw.replace(/```json\s*/gi, "").replace(/```\s*/g, "").trim();
    res.json(JSON.parse(clean));
  } catch (err) {
    res.status(500).json({ error: "Failed to generate notes. Please try again." });
  }
});

// ── RAZORPAY: Create Donation Order ──────────────────────────────────────────
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

// ── RAZORPAY: Verify Donation ─────────────────────────────────────────────────
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

// ── STUDY ROOMS ───────────────────────────────────────────────────────────────
const rooms = new Map();

function generateCode() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
}

function getOrCreateRoom(code) {
  if (!rooms.has(code)) {
    rooms.set(code, { members: {}, clients: new Set(), createdAt: Date.now() });
  }
  return rooms.get(code);
}

function broadcastToRoom(code, data) {
  const room = rooms.get(code);
  if (!room) return;
  const msg = 'data: ' + JSON.stringify(data) + '\n\n';
  room.clients.forEach(client => {
    try { client.res.write(msg); } catch(e) {}
  });
}

setInterval(() => {
  const now = Date.now();
  rooms.forEach((room, code) => {
    if (now - room.createdAt > 7200000) rooms.delete(code);
  });
}, 3600000);

app.post("/api/room/create", authMiddleware, (req, res) => {
  let code = generateCode();
  while (rooms.has(code)) code = generateCode();
  getOrCreateRoom(code);
  res.json({ code });
});

app.post("/api/room/join", authMiddleware, (req, res) => {
  const { code, name, picture } = req.body;
  const room = getOrCreateRoom(code);
  room.members[req.user.email] = { email: req.user.email, name: name || req.user.name, picture: picture || '' };
  broadcastToRoom(code, { type: 'members', members: room.members });
  res.json({ success: true });
});

app.post("/api/room/leave", authMiddleware, (req, res) => {
  const { code } = req.body;
  const room = rooms.get(code);
  if (room) {
    delete room.members[req.user.email];
    room.clients.forEach(c => { if (c.email === req.user.email) room.clients.delete(c); });
    broadcastToRoom(code, { type: 'members', members: room.members });
    if (Object.keys(room.members).length === 0) rooms.delete(code);
  }
  res.json({ success: true });
});

app.get("/api/room/events", (req, res) => {
  const { code, token } = req.query;
  if (!code || !token) return res.status(400).end();
  const payload = verifyToken(token);
  if (!payload) return res.status(401).end();
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();
  const room = getOrCreateRoom(code);
  const client = { email: payload.email, res };
  room.clients.add(client);
  res.write('data: ' + JSON.stringify({ type: 'members', members: room.members }) + '\n\n');
  const heartbeat = setInterval(() => {
    try { res.write('data: ' + JSON.stringify({ type: 'ping' }) + '\n\n'); }
    catch(e) { clearInterval(heartbeat); }
  }, 25000);
  req.on('close', () => {
    clearInterval(heartbeat);
    room.clients.delete(client);
  });
});

app.post("/api/room/broadcast", authMiddleware, (req, res) => {
  const { code, type, ...data } = req.body;
  const room = rooms.get(code);
  if (!room) return res.status(404).json({ error: 'Room not found' });
  broadcastToRoom(code, { type, ...data });
  res.json({ success: true });
});

// ── AI DOUBT SOLVER ───────────────────────────────────────────────────────────
app.post("/api/doubt", authMiddleware, async (req, res) => {
  const { context, question } = req.body;
  if (!question) return res.status(400).json({ error: "Question is required" });
  const systemPrompt = `You are a friendly, smart study assistant helping an Indian student understand their topic.
Context: ${(context || '').substring(0, 1500)}
Rules: Answer clearly and simply. Use emojis occasionally. Keep answers concise (2-4 sentences). Give relatable Indian student examples when helpful.`;
  try {
    const response = await fetch(GROQ_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${GROQ_API_KEY}` },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [{ role: "system", content: systemPrompt }, { role: "user", content: question }],
        temperature: 0.7, max_tokens: 512
      })
    });
    const data = await response.json();
    if (!response.ok) {
      if (response.status === 429) return res.status(429).json({ error: "AI is busy! Try again in a moment." });
      return res.status(500).json({ error: "Could not get answer. Try again!" });
    }
    res.json({ answer: data.choices?.[0]?.message?.content || "Sorry, I could not answer that!" });
  } catch (err) {
    res.status(500).json({ error: "Failed to get answer. Please try again." });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`StudySnap running on port ${PORT}`));

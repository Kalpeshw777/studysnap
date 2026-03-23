const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const { MongoClient } = require("mongodb");
const { OAuth2Client } = require("google-auth-library");

const app = express();
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://noteninja.is-a.dev']
    : ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' })); // Limit request body size
app.use(express.static(path.join(__dirname, "public")));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// Simple in-memory rate limiter per IP (100 requests per 15 minutes)
const rateLimitMap = new Map();
app.use('/api', (req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const maxRequests = 100;
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
  } else {
    const data = rateLimitMap.get(ip);
    if (now > data.resetTime) {
      rateLimitMap.set(ip, { count: 1, resetTime: now + windowMs });
    } else if (data.count >= maxRequests) {
      return res.status(429).json({ error: 'Too many requests. Please slow down.' });
    } else {
      data.count++;
    }
  }
  next();
});
// Clean up rate limit map every 30 minutes
setInterval(() => {
  const now = Date.now();
  rateLimitMap.forEach((data, ip) => { if (now > data.resetTime) rateLimitMap.delete(ip); });
}, 1800000);

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

// ── GENERATE NOTES — NO LIMITS ────────────────────────────────────────────────
app.post("/api/generate", authMiddleware, async (req, res) => {
  let { topic, level, depth } = req.body;
  if (!topic) return res.status(400).json({ error: "Topic is required" });
  topic = String(topic).trim().substring(0, 200).replace(/[<>]/g, "");
  level = ["beginner","intermediate","advanced"].includes(level) ? level : "intermediate";
  depth = ["quick","standard","deep"].includes(depth) ? depth : "standard";
  if (topic.length < 2) return res.status(400).json({ error: "Topic too short" });

  // Track usage in DB (no limits — just analytics)
  await db.collection("users").updateOne(
    { email: req.user.email },
    { $inc: { totalGenerations: 1 }, $set: { lastUsed: new Date() } }
  );

  const numPoints = depth === "quick" ? 5 : depth === "deep" ? 15 : 10;
  const prompt = `You are an expert study assistant and educator. Generate accurate, detailed study notes for the topic: "${topic}" at ${level || "intermediate"} level.
You MUST respond with ONLY valid JSON — no markdown fences, no explanation, no extra text before or after.
Use this exact JSON structure:
{"definition":"2-3 sentence overview","points":[{"title":"Concept","text":"Explanation with <strong>key terms</strong>"}],"formulas":["formula if applicable"],"qa":[{"q":"Question?","a":"Answer.","diff":"easy"}]}
Rules: ${numPoints} points, EXACTLY 10 qa items (these are used for both Q&A and MCQ flashcards so make them varied and clear), diff = easy/medium/hard mix, empty formulas array if none, use <strong> tags in points text only`;

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
  // Mark user as supporter
  await db.collection("users").updateOne(
    { email: req.user.email },
    { $set: { supporter: true, supportedAt: new Date(), lastPaymentId: razorpay_payment_id } }
  );
  res.json({ success: true });
});



// ── STUDY ROOMS ───────────────────────────────────────────────────────────────
// In-memory rooms store (fast, no DB needed for ephemeral rooms)
const rooms = new Map(); // code -> { members, clients, createdAt }

function generateCode() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
}

function getOrCreateRoom(code) {
  if (!rooms.has(code)) {
    rooms.set(code, { members: {}, clients: new Set(), createdAt: Date.now() });
  }
  return rooms.get(code);
}

function broadcastToRoom(code, data, excludeEmail = null) {
  const room = rooms.get(code);
  if (!room) return;
  const msg = 'data: ' + JSON.stringify(data) + '\n\n';
  room.clients.forEach(client => {
    if (excludeEmail && client.email === excludeEmail) return;
    try { client.res.write(msg); } catch(e) {}
  });
}

// Clean up old rooms every 2 hours
setInterval(() => {
  const now = Date.now();
  rooms.forEach((room, code) => {
    if (now - room.createdAt > 7200000) rooms.delete(code);
  });
}, 3600000);

// Create room
app.post("/api/room/create", authMiddleware, (req, res) => {
  let code = generateCode();
  while (rooms.has(code)) code = generateCode();
  getOrCreateRoom(code);
  res.json({ code });
});

// Join room
app.post("/api/room/join", authMiddleware, (req, res) => {
  const { code, name, picture } = req.body;
  const room = getOrCreateRoom(code);
  room.members[req.user.email] = { email: req.user.email, name: name || req.user.name, picture: picture || '' };
  broadcastToRoom(code, { type: 'members', members: room.members });
  res.json({ success: true });
});

// Leave room
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

// SSE events stream
app.get("/api/room/events", (req, res) => {
  const { code, token } = req.query;
  if (!code || !token) return res.status(400).end();
  
  // Verify token
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

  // Send current members immediately
  res.write('data: ' + JSON.stringify({ type: 'members', members: room.members }) + '\n\n');

  // Heartbeat every 25s
  const heartbeat = setInterval(() => {
    try { res.write('data: ' + JSON.stringify({ type: 'ping' }) + '\n\n'); }
    catch(e) { clearInterval(heartbeat); }
  }, 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    room.clients.delete(client);
  });
});

// Broadcast event to room
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
You have these notes as context: ${(context || '').substring(0, 1500)}

Rules:
- Answer clearly and simply
- Use emojis occasionally to keep it engaging  
- Keep answers concise (2-4 sentences) unless detail is needed
- Give relatable Indian student examples when helpful
- If you don't know something from the context, say so honestly`;

  try {
    const response = await fetch(GROQ_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${GROQ_API_KEY}` },
      body: JSON.stringify({
        model: "llama-3.3-70b-versatile",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: question }
        ],
        temperature: 0.7,
        max_tokens: 512
      })
    });
    const data = await response.json();
    if (!response.ok) {
      const errMsg = data.error?.message || "";
      if (errMsg.includes("rate_limit") || response.status === 429) {
        return res.status(429).json({ error: "AI is busy! Please try again in a moment." });
      }
      return res.status(500).json({ error: "Could not get answer. Try again!" });
    }
    const answer = data.choices?.[0]?.message?.content || "Sorry, I could not answer that!";
    res.json({ answer });
  } catch (err) {
    res.status(500).json({ error: "Failed to get answer. Please try again." });
  }
});


// ── FEEDBACK ──────────────────────────────────────────────────────────────────
app.post("/api/feedback", authMiddleware, async (req, res) => {
  let { type, rating, message, page } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });
  message = String(message).trim().substring(0, 1000);
  type = ['suggestion','bug','love','other'].includes(type) ? type : 'other';
  rating = Math.min(5, Math.max(0, parseInt(rating) || 0));
  page = String(page || '').substring(0, 200);
  try {
    // Save to MongoDB
    await db.collection("feedback").insertOne({
      email: req.user.email,
      type: type || 'general',
      rating: rating || 0,
      message,
      page: page || '',
      userAgent: userAgent || '',
      createdAt: new Date()
    });

    // Log feedback to console so it appears in Render logs
    console.log('[FEEDBACK]', JSON.stringify({ type, rating, message, email: req.user.email }));
    res.json({ success: true });
  } catch(err) {
    res.status(500).json({ error: "Failed to save feedback" });
  }
});

// ── VIEW FEEDBACK (admin only) ────────────────────────────────────────────────
app.get("/api/feedback/all", authMiddleware, async (req, res) => {
  const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'kalpeshwadile6@gmail.com';
  if (req.user.email !== ADMIN_EMAIL) return res.status(403).json({ error: "Not authorized" });
  try {
    const feedback = await db.collection("feedback")
      .find({})
      .sort({ createdAt: -1 })
      .limit(100)
      .toArray();
    res.json(feedback);
  } catch(err) {
    res.status(500).json({ error: "Failed to fetch feedback" });
  }
});

// ── HEALTH CHECK ─────────────────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

// ── 404 HANDLER ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(require('path').join(__dirname, 'public', 'index.html'));
});

// ── GRACEFUL SHUTDOWN ─────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => console.log(`NoteNinja running on port ${PORT}`));

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

const express = require("express");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const { MongoClient } = require("mongodb");
const { OAuth2Client } = require("google-auth-library");

const app = express();
// Request logger
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    if (req.path.startsWith('/api/')) {
      console.log(`${req.method} ${req.path} ${res.statusCode} ${ms}ms`);
    }
  });
  next();
});

app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? [
        'https://noteninja.online',
        'https://www.noteninja.online',
        'https://studysnap-tsxk.onrender.com'
      ]
    : ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' })); // Limit request body size
app.use(express.static(path.join(__dirname, "public"), {
  maxAge: '1d',
  etag: true,
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  }
}));

// Security headers (applied to all routes EXCEPT SEO files)
app.use((req, res, next) => {
  // Skip strict headers for SEO/crawler files — Google needs clean responses
  const seoRoutes = ['/sitemap.xml', '/robots.txt', '/ads.txt'];
  if (seoRoutes.includes(req.path)) return next();
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
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
      userAgent: req.headers['user-agent'] || '',
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

// NOTE: robots.txt and ads.txt are static files in public/ — more reliable for crawlers.

// ── SEO: sitemap.xml ──────────────────────────────────────────────────────────
app.get('/sitemap.xml', (req, res) => {
  const now = new Date().toISOString().split('T')[0];
  const xml = '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n' +
    '        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n' +
    '        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9\n' +
    '        http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">\n' +
    '  <url>\n' +
    '    <loc>https://noteninja.online/</loc>\n' +
    '    <lastmod>' + now + '</lastmod>\n' +
    '    <changefreq>weekly</changefreq>\n' +
    '    <priority>1.0</priority>\n' +
    '  </url>\n' +
    '  <url>\n' +
    '    <loc>https://noteninja.online/privacy-policy</loc>\n' +
    '    <lastmod>' + now + '</lastmod>\n' +
    '    <changefreq>monthly</changefreq>\n' +
    '    <priority>0.3</priority>\n' +
    '  </url>\n' +
    '  <url>\n' +
    '    <loc>https://noteninja.online/terms</loc>\n' +
    '    <lastmod>' + now + '</lastmod>\n' +
    '    <changefreq>monthly</changefreq>\n' +
    '    <priority>0.3</priority>\n' +
    '  </url>\n' +
    '</urlset>';
  res.setHeader('Content-Type', 'application/xml; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.status(200).end(xml);
});

// NOTE: ads.txt is a static file in public/ads.txt

// ── PRIVACY POLICY ────────────────────────────────────────────────────────────
app.get('/privacy-policy', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  const today = new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });
  const year = new Date().getFullYear();
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Privacy Policy — NoteNinja</title>
  <meta name="description" content="Privacy Policy for NoteNinja — AI-powered exam helper for Indian students."/>
  <meta name="robots" content="index, follow"/>
  <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-6423436827122681" crossorigin="anonymous"></script>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Segoe UI',system-ui,sans-serif;background:#080808;color:#e0e0e0;line-height:1.8}
    .header{background:#111;border-bottom:1px solid #222;padding:16px 24px;display:flex;align-items:center;gap:12px}
    .header a{color:#e63329;text-decoration:none;font-weight:700;font-size:1.1rem}
    .header span{color:#555;font-size:0.85rem}
    .container{max-width:760px;margin:0 auto;padding:40px 24px 80px}
    h1{font-size:1.8rem;color:#f0f0f0;margin-bottom:6px}
    .date{color:#555;font-size:0.82rem;margin-bottom:36px;font-family:monospace}
    h2{font-size:1.05rem;color:#e63329;margin:32px 0 10px;font-family:monospace;text-transform:uppercase;letter-spacing:0.5px}
    p{color:#aaa;margin-bottom:12px;font-size:0.92rem}
    a{color:#e63329}
    ul{color:#aaa;font-size:0.92rem;padding-left:20px;margin-bottom:12px}
    ul li{margin-bottom:6px}
    .footer{margin-top:40px;padding-top:20px;border-top:1px solid #222;color:#555;font-size:0.8rem}
  </style>
</head>
<body>
  <div class="header">
    <a href="/">🥷 NoteNinja</a>
    <span>/ Privacy Policy</span>
  </div>
  <div class="container">
    <h1>Privacy Policy</h1>
    <div class="date">Last updated: ${today}</div>
    <p>NoteNinja ("we", "us") operates <strong>noteninja.online</strong>. This Privacy Policy explains how we collect, use, and protect your information.</p>

    <h2>Information We Collect</h2>
    <ul>
      <li><strong>Account data:</strong> When you sign in with Google, we receive your name, email address, and profile picture.</li>
      <li><strong>Usage data:</strong> Topics you generate and feature usage counts (stored anonymously for analytics).</li>
      <li><strong>Technical data:</strong> IP address (for rate limiting), browser user-agent, and API call timestamps.</li>
    </ul>

    <h2>How We Use Your Data</h2>
    <ul>
      <li>To authenticate your account and keep you signed in</li>
      <li>To generate AI-powered study notes, flashcards, and MCQs</li>
      <li>To track aggregate usage for product improvement</li>
      <li>To send smart revision reminders you opt into</li>
    </ul>

    <h2>Google AdSense & Advertising</h2>
    <p>We use <strong>Google AdSense</strong> to display advertisements. Google may use cookies to serve ads based on your visits to this and other websites. You can opt out at <a href="https://www.google.com/settings/ads" target="_blank" rel="noopener">Google Ad Settings</a> or <a href="https://www.aboutads.info" target="_blank" rel="noopener">aboutads.info</a>.</p>

    <h2>Third-Party Services</h2>
    <ul>
      <li><strong>Google OAuth</strong> — Authentication. Subject to <a href="https://policies.google.com/privacy" target="_blank" rel="noopener">Google's Privacy Policy</a>.</li>
      <li><strong>Groq API</strong> — AI content generation. Topic queries are sent to Groq servers.</li>
      <li><strong>MongoDB Atlas</strong> — Cloud database for account and feedback data.</li>
      <li><strong>Razorpay</strong> — Payment processing for optional support. Card details are never stored by us.</li>
    </ul>

    <h2>Cookies</h2>
    <ul>
      <li><strong>localStorage:</strong> Your auth token and notes history are stored in your browser only.</li>
      <li><strong>Google AdSense cookies:</strong> For ad personalisation (can be disabled via Google Ad Settings).</li>
    </ul>

    <h2>Data Retention</h2>
    <p>Account data is retained while your account is active. Notes history exists only in your browser's localStorage and is never uploaded to our servers.</p>

    <h2>Children's Privacy</h2>
    <p>NoteNinja is for students aged 13 and above. We do not knowingly collect data from children under 13.</p>

    <h2>Security</h2>
    <p>We implement HTTPS, rate limiting, input sanitisation, and CORS restrictions to protect your data.</p>

    <h2>Contact</h2>
    <p>For privacy questions or data deletion: <a href="mailto:kalpeshwadile6@gmail.com">kalpeshwadile6@gmail.com</a></p>

    <div class="footer">
      <p>© ${year} NoteNinja. All rights reserved. | <a href="/terms">Terms of Service</a> | <a href="/">Back to NoteNinja</a></p>
    </div>
  </div>
</body>
</html>`);
});

// ── TERMS OF SERVICE ──────────────────────────────────────────────────────────
app.get('/terms', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  const today = new Date().toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });
  const year = new Date().getFullYear();
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Terms of Service — NoteNinja</title>
  <meta name="description" content="Terms of Service for NoteNinja — AI-powered exam helper for Indian students."/>
  <meta name="robots" content="index, follow"/>
  <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-6423436827122681" crossorigin="anonymous"></script>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:'Segoe UI',system-ui,sans-serif;background:#080808;color:#e0e0e0;line-height:1.8}
    .header{background:#111;border-bottom:1px solid #222;padding:16px 24px;display:flex;align-items:center;gap:12px}
    .header a{color:#e63329;text-decoration:none;font-weight:700;font-size:1.1rem}
    .header span{color:#555;font-size:0.85rem}
    .container{max-width:760px;margin:0 auto;padding:40px 24px 80px}
    h1{font-size:1.8rem;color:#f0f0f0;margin-bottom:6px}
    .date{color:#555;font-size:0.82rem;margin-bottom:36px;font-family:monospace}
    h2{font-size:1.05rem;color:#e63329;margin:32px 0 10px;font-family:monospace;text-transform:uppercase;letter-spacing:0.5px}
    p{color:#aaa;margin-bottom:12px;font-size:0.92rem}
    a{color:#e63329}
    ul{color:#aaa;font-size:0.92rem;padding-left:20px;margin-bottom:12px}
    ul li{margin-bottom:6px}
    .footer{margin-top:40px;padding-top:20px;border-top:1px solid #222;color:#555;font-size:0.8rem}
  </style>
</head>
<body>
  <div class="header">
    <a href="/">🥷 NoteNinja</a>
    <span>/ Terms of Service</span>
  </div>
  <div class="container">
    <h1>Terms of Service</h1>
    <div class="date">Last updated: ${today}</div>
    <p>By using NoteNinja at <strong>noteninja.online</strong>, you agree to these Terms. If you disagree, please stop using the service.</p>

    <h2>Use of Service</h2>
    <ul>
      <li>NoteNinja is a free AI-powered study tool for students.</li>
      <li>You must be at least 13 years old to use this service.</li>
      <li>Do not misuse the service — including bypassing rate limits, reverse-engineering, or overloading our servers.</li>
      <li>AI-generated content is for study assistance only and may not always be 100% accurate. Verify critical information independently.</li>
    </ul>

    <h2>Intellectual Property</h2>
    <p>The NoteNinja platform, design, and branding are owned by NoteNinja. AI-generated notes are for your personal educational use only.</p>

    <h2>Advertising</h2>
    <p>NoteNinja displays third-party ads via Google AdSense to keep the service free. By using NoteNinja, you consent to the display of these ads.</p>

    <h2>Disclaimer</h2>
    <p>NoteNinja provides AI-generated content "as is" without warranties of accuracy. We are not liable for errors in AI-generated content or decisions made based on it.</p>

    <h2>Termination</h2>
    <p>We may suspend or terminate access for users who violate these Terms or abuse the platform.</p>

    <h2>Changes</h2>
    <p>We may update these Terms occasionally. Continued use after changes means you accept the updated Terms.</p>

    <h2>Contact</h2>
    <p>Questions? Email: <a href="mailto:kalpeshwadile6@gmail.com">kalpeshwadile6@gmail.com</a></p>

    <div class="footer">
      <p>© ${year} NoteNinja. All rights reserved. | <a href="/privacy-policy">Privacy Policy</a> | <a href="/">Back to NoteNinja</a></p>
    </div>
  </div>
</body>
</html>`);
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

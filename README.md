# NoteNinja — AI Exam Helper

## Setup & Deploy 

### Step 1 — Install dependencies
```
npm install
```

### Step 2 — Test locally
```
npm start
```
Open http://localhost:3000

### Step 3 — Push to GitHub
```
git init
git add .
git commit -m "StudySnap initial commit"
git remote add origin https://github.com/YOUR_USERNAME/studysnap.git
git push -u origin main
```

### Step 4 — Deploy on Render
1. Go to render.com → New Web Service
2. Connect your GitHub repo
3. Settings:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
4. Add Environment Variable:
   - Key: `GEMINI_API_KEY`
   - Value: your Gemini API key
5. Click Deploy ✓

## Project Structure
```
studysnap/
├── server.js        ← Express backend (Groq proxy)
├── package.json
└── public/
    └── index.html   ← Frontend
```

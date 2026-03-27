# 🔐 VulnDetectRAG — Project Explanation (For Complete Beginners)

> **What is this project?**
> Imagine you have a security guard robot 🤖 that can look at any website or computer server on the internet, check if it has any weak spots (called **vulnerabilities**), tell you how dangerous those weak spots are, and answer your questions about them in plain English. That's exactly what **VulnDetectRAG** does.
>
> **RAG** stands for *Retrieval-Augmented Generation* — a fancy way of saying the AI assistant looks up real information from a database before answering, instead of just guessing.
>
> **🔒 Privacy First (Zero External APIs):** We have entirely removed external API dependencies (like OpenAI). This platform now runs a **100% Local LLM** (via Ollama). Your security data stays on your machine and never goes to the cloud!

---

## 📦 Project Structure Overview

```
vuln-detect-rag/
│
├── 📁 backend/          ← The brain of the application (Python)
├── 📁 frontend/         ← The face of the application (React website)
├── 📁 scripts/          ← Helper tools run once to set up data
│
├── Run_VulnDetect.bat   ← One-click launcher for everything
├── requirements.txt     ← List of Python packages needed
├── .env.example         ← Template for secret settings
├── roadmap.md           ← Future plans for the project
└── README.md            ← Quick-start guide
```

---

## 🌊 How the Whole System Works (The Big Picture)

```
YOU (the user)
    │
    │  Open browser → http://localhost:5173
    ▼
┌─────────────────────────────┐
│     FRONTEND (React App)    │  ← The pretty website you see
│  Dashboard, Scan Console,   │
│  AI Chat, CVE Browser       │
└────────────┬────────────────┘
             │  Sends requests (like "scan this website!")
             ▼
┌─────────────────────────────┐
│    BACKEND (FastAPI API)    │  ← The engine room
│   Python + SQLite Database  │
└────┬───────┬────────────────┘
     │       │
     ▼       ▼
 Scanners   AI (RAG Engine)
 (nmap,     (answers your
  nuclei)    questions)
```

---

## 🏠 Root-Level Files

### `Run_VulnDetect.bat` — The Magic Button ✨
> **ELI5:** This is the "Start Everything" button. Double-click it and it turns the whole project on automatically.

- Checks if Python is installed
- Checks if Node.js is installed
- Creates a Python environment and installs all libraries
- Starts the backend server
- Installs frontend packages (first time only) and starts the website
- Opens your browser to `http://localhost:5173`
- You leave two black terminal windows open — closing them shuts down the app

---

### `requirements.txt` — Shopping List for Python
> **ELI5:** Before cooking a meal, you need a grocery list. This file tells Python which ingredient libraries to download (FastAPI, SQLAlchemy, ChromaDB, LangChain, etc.)

---

### `.env.example` — Template for Secret Settings
> **ELI5:** A fill-in-the-blank form. You copy this file, rename it `.env`, and fill in your local settings. Nobody else should ever see your filled-in version.

Key settings include:
- `OLLAMA_BASE_URL` / `OLLAMA_MODEL` — local LLM configuration (uses Ollama with qwen2.5-coder:7b)
- `DATABASE_URL` — where to save scan data (defaults to a local SQLite file)
- `NMAP_PATH` / `NUCLEI_PATH` — locations of scanner tools on your computer

---

### `roadmap.md` — Future Plans
> **ELI5:** A wish list of features the team wants to build next.

---

### `README.md` — Quick-Start Instructions
> **ELI5:** The "read me first" instruction booklet that came in the box.

---

## ⚙️ BACKEND — The Engine Room

The backend is a **Python web server** built with **FastAPI**. It's what actually does all the security scanning and database storing. The frontend never talks to the internet directly — it always asks the backend first.

```
backend/
├── main.py              ← Entry point. Starts the server.
├── config.py            ← Load settings from .env file
│
├── 📁 api/              ← URL routes (what URLs do what)
│   ├── routes_scan.py   ← /api/scans - start & manage scans
│   ├── routes_rag.py    ← /api/rag - AI chat assistant
│   └── routes_cve.py    ← /api/cve - search vulnerability database
│
├── 📁 services/         ← Business logic (the real brains)
│   ├── orchestrator.py  ← Coordinates all the scanners
│   ├── aggregator.py    ← Cleans up and combines scan results
│   ├── rag_engine.py    ← The AI question-answering engine
│   ├── attack_path.py   ← Figures out how an attacker could move
│   └── evaluators.py    ← Grades how accurate the AI answers are
│
├── 📁 scanners/         ← Security scanning tools
│   ├── base.py          ← Blueprint all scanners must follow
│   ├── nmap_scanner.py  ← Port & service scanner
│   ├── nuclei_scanner.py← Web vulnerability scanner
│   ├── nessus_scanner.py← Nessus scanner connector (stub)
│   └── openvas_scanner.py← OpenVAS scanner connector (stub)
│
├── 📁 models/           ← Database table definitions
│   ├── database.py      ← Table structures (Scans, Vulns, CVEs, Chats)
│   └── schemas.py       ← Data shapes for API requests/responses
│
├── 📁 data/             ← Where the database files are stored
├── .env                 ← Your actual secret settings (never share!)
├── backend.log          ← Log of everything that happened
└── requirements.txt     ← Python packages for the backend only
```

---

### `backend/main.py` — The Server Starter 🚀
> **ELI5:** This is like the front door of a restaurant. Every request that comes in walks through here first. It takes care of:
> - Starting the server
> - Creating the database on first run
> - Checking who's allowed in (CORS — lets the frontend talk to the backend)
> - Rate limiting — if someone sends too many requests too fast, it says "slow down!" (like a bouncer)
> - Logging every request so you can see what happened
> - Catching any crashes and returning a friendly error message instead of crashing completely

**Key Endpoints defined here:**
- `GET /` → Says "hello, I'm running!"
- `GET /api/health` → Reports which scanners are installed
- `GET /api/logs` → Shows the last 500 lines of the log file

---

### `backend/config.py` — The Settings Manager ⚙️
> **ELI5:** Like a settings menu in a game. It reads your `.env` file and makes all the settings available everywhere in the app.

Important settings:
| Setting | What it does |
|---|---|
| `APP_VERSION` | Current version (1.3.0) |
| `DATABASE_URL` | Path to the SQLite database file |
| `CHROMA_PERSIST_DIR` | Where the AI's memory (vector database) is stored |
| `OLLAMA_BASE_URL` | URL where Ollama is running (default: http://localhost:11434) |
| `OLLAMA_MODEL` | Which local LLM model to use (default: qwen2.5-coder:7b) |
| `CORS_ORIGINS` | Which websites are allowed to talk to the backend |

---

## 📡 API Routes — The URL Handlers

### `backend/api/routes_scan.py` — Scan Controller 🔬
> **ELI5:** This is the "request desk" for scans. You tell it a website to scan, and it creates a scan job and runs it in the background while you wait.

**What URLs it handles:**
```
POST   /api/scans          → Start a new scan (e.g. scan "example.com")
GET    /api/scans/{id}     → Check how a scan is going (progress %)
GET    /api/scans/{id}/results → Get all the vulnerabilities found
GET    /api/scans/{id}/attack-paths → See how an attacker could exploit the findings
GET    /api/scans/{id}/export → Download results as JSON or CSV file
GET    /api/scans          → List all past scans
DELETE /api/scans/{id}     → Delete a scan
GET    /api/stats          → Dashboard numbers (total scans, total vulns, etc.)
POST   /api/favorites      → Save a target to your favorites list
GET    /api/favorites      → List your favorite targets
DELETE /api/favorites/{id} → Remove a favorite
```

**Security note:** The route validates the target — it blocks scanning `localhost`, private IPs (like `192.168.x.x`), and loopback addresses. You can only scan real public internet targets.

---

### `backend/api/routes_rag.py` — AI Chat Controller 🤖
> **ELI5:** This handles the chat window where you ask questions like "What is Log4Shell?" and the AI looks it up and answers you.

**What URLs it handles:**
```
POST   /api/rag/chat              → Send a question, get an AI answer
GET    /api/rag/history/{sid}     → Get past messages from a chat session
GET    /api/rag/sessions          → List all your chat sessions
DELETE /api/rag/sessions/{sid}    → Delete a chat session
POST   /api/rag/index             → Re-load CVE data into the AI's memory
```

---

### `backend/api/routes_cve.py` — CVE Database Controller 📚
> **ELI5:** CVEs are like named security bugs (e.g. "CVE-2021-44228" = Log4Shell). This lets you search through a database of them.

**What URLs it handles:**
```
GET /api/cve               → Search CVEs by keyword, severity, or if they have an exploit
GET /api/cve/{cve_id}      → Look up one specific CVE by name
GET /api/cve/stats/severity → Get counts per severity level (how many CRITICAL, HIGH, etc.)
```

---

## 🧠 Services — The Business Logic

### `backend/services/orchestrator.py` — The Scan Manager 🎯
> **ELI5:** Imagine you're a manager at a security firm. A client calls in and says "check my website". You assign different specialists (Nmap, Nuclei) to check different things simultaneously, then collect all their reports when done, and file the summary. That's the orchestrator.

**What it does step by step:**
```
1. Client says "scan example.com with nmap + nuclei"
   ↓
2. Creates a scan record in the database (status: "pending")
   ↓
3. Loops through each scanner one at a time:
   - Updates progress percentage (0% → 80%)
   - Runs the scanner in a background thread (so the server doesn't freeze)
   - Collects the list of vulnerabilities found
   ↓
4. Sends all results to the Aggregator for cleaning up
   ↓
5. Counts: Critical/High/Medium/Low vulnerabilities, calculates average CVSS score
   ↓
6. Updates scan record to "completed" with final stats
   ↓
7. If anything crashes → marks scan as "failed" with error details
```

---

### `backend/services/aggregator.py` — The Data Cleaner 🧹
> **ELI5:** If two scanners both find the same bug, you don't want to count it twice. The aggregator removes duplicates, picks the highest CVSS score when there are duplicates, and saves everything cleanly to the database.

**Rules it follows:**
- Uses CVE ID as the unique key; if no CVE ID, uses `host:port:description` as the key
- Keeps the entry with the **higher CVSS score** when there's a duplicate
- Merges reference links from both duplicate entries
- Converts CVSS scores to severity labels:
  - `≥ 9.0` → **CRITICAL**
  - `≥ 7.0` → **HIGH**
  - `≥ 4.0` → **MEDIUM**
  - `< 4.0` → **LOW**

---

### `backend/services/rag_engine.py` — The AI Brain 🧬
> **ELI5:** Think of this as a very smart librarian. You ask a question. The librarian searches through a special library (ChromaDB) of known security bugs. It pulls out the 5 most relevant books/articles. Then either:
> - **With local LLM (Ollama):** Gives those articles to the completely offline, local AI model (no external API calls!) and asks it to write a clear answer
> - **Without local LLM:** Just lists the relevant CVEs it found in a structured format

**The two modes:**
```
[With Local LLM via Ollama]
User question → ChromaDB search → Top 5 similar CVE entries →
→ qwen2.5-coder:7b (local) → Smart paragraph answer

[Without Local LLM — Fallback Mode]
User question → ChromaDB search → Top 5 similar CVE entries →
→ Formatted bullet-point list of CVE IDs, severities, CVSS scores
```

**Auto-detection:** The engine runs `ollama list` to detect installed models. The RAG Assistant page shows a green banner when a model is found, or a red "No local LLM" warning if not.

**Smart embedding:** The AI converts questions and CVE descriptions into numbers (vectors) so it can find "similar meaning" even if the exact words don't match. Uses the free `all-MiniLM-L6-v2` model by default.

---

### `backend/services/attack_path.py` — The Hacker Simulator 🗺️
> **ELI5:** After scanning, this service asks: "If a real hacker found these vulnerabilities, what path would they take to break deeper into the system?" It builds a map like a board game — starting from Entry Point → Vulnerability → Lateral Movement → Other Servers.

**How it builds the map:**
```
For each vulnerability found:
  - Creates a "Host" node (the server)
  - Creates a "Vulnerability" node (the CVE)
  - Creates a "Service" node (e.g. "http:443")
  - Draws arrows: Host → Service → Vulnerability

For CRITICAL vulnerabilities with known exploits:
  - Draws "lateral movement" arrows from that vuln to other hosts
  (simulating: attacker uses this bug to jump to the next machine)

Then finds all possible paths from start to end
Sorts them by total CVSS score (most dangerous first)
Returns top 20 most dangerous paths
```

**Risk levels for a path:**
- Total CVSS > 15 → **CRITICAL path**
- Total CVSS > 10 → **HIGH path**
- Otherwise → **MEDIUM path**

---

### `backend/services/evaluators.py` — The Quality Grader 📊
> **ELI5:** How do you know if the AI's answers are any good? This file grades the AI like a teacher. It uses standard NLP (text quality) metrics.

**Three metrics it calculates:**
1. **CVE Detection (F1 Score)** — Did the AI find the right CVEs? Measures precision (no false alarms) and recall (didn't miss anything)
2. **BLEU Score** — Are the words in the AI's answer similar to a reference answer? (Used in machine translation, now used here)
3. **ROUGE Score** — How much overlap is there between the AI's answer and a reference? (3 variants: word overlap, bigram overlap, longest common sequence)

---

## 🔍 Scanners — The Security Tools

### `backend/scanners/base.py` — The Scanner Blueprint 📐
> **ELI5:** A recipe template. Every scanner must follow the same recipe: have a `scan(target)` method that returns a list of `ScanVulnerability` objects. This ensures all scanners produce the same format of results.

**`ScanVulnerability` fields:**
| Field | Example |
|---|---|
| `cve_id` | "CVE-2021-44228" |
| `cvss_score` | 10.0 |
| `severity` | "CRITICAL" |
| `description` | "Apache Log4j RCE" |
| `affected_host` | "example.com" |
| `affected_port` | 443 |
| `affected_service` | "https" |
| `solution` | "Update to Log4j 2.17.1" |
| `exploit_available` | True |
| `source_scanner` | "nmap" |

---

### `backend/scanners/nmap_scanner.py` — The Port Inspector 🔌
> **ELI5:** Nmap is like a knock test — it knocks on all the doors (ports) of a server and notes which are open and what's running behind them. Then it checks if anything running is known to be vulnerable.

**What it does:**
```
1. Checks if "nmap" is installed on the computer
2. If YES → runs: nmap -sV -sC --script vulners -oX - -T4 --top-ports 1000 [target]
   - -sV: detect what software version is running on each port
   - -sC: run default scripts
   - --script vulners: check for known CVEs using the vulners database
   - --top-ports 1000: check the 1000 most common ports
   - -oX -: output as XML to be parsed
3. Parses the XML output to extract CVE IDs and CVSS scores
4. Also extracts open port information even without CVEs
5. If nmap is NOT installed → uses mock data for demo purposes
```

**Mock data (when nmap is not installed):** Returns realistic-looking fake vulnerabilities like Log4Shell, Spring4Shell, HTTP/2 Rapid Reset etc., seeded by the target's hash so the same target always gets the same "fake" results.

---

### `backend/scanners/nuclei_scanner.py` — The Web Vulnerability Scanner 🌐
> **ELI5:** Nuclei is like a security checklist. It has thousands of templates — each one tests for a specific known web vulnerability. It runs all relevant templates against the target website and reports what it finds.

**What it does:**
```
1. Checks if "nuclei" is installed
2. Runs: nuclei -u [target] -jsonl -silent -severity critical,high,medium
   - -jsonl: output one JSON per line (easy to parse)
   - -severity: only report critical/high/medium findings
3. Each line of output is one finding; parses CVE IDs, descriptions, remediation
4. Deduplicates results by template + matched URL
5. Falls back to mock data if nuclei is not installed
```

---

### `backend/scanners/nessus_scanner.py` — Nessus Connector (Stub) 🔌
> **ELI5:** Nessus is a professional (paid) security scanner. This file is a connector for it — right now it always returns mock data because Nessus requires a license and a separate server to be running.

---

### `backend/scanners/openvas_scanner.py` — OpenVAS Connector (Stub) 🔌
> **ELI5:** OpenVAS is a free professional security scanner. Like Nessus, this connector exists but currently returns mock data because OpenVAS requires a complex installation.

---

## 🗃️ Models — The Database Layer

### `backend/models/database.py` — The Database Structure 🏗️
> **ELI5:** This defines the "filing cabinets" that hold all the data. Like designing the drawers and folders before you start filing.

**5 tables:**
| Table | What's stored |
|---|---|
| `scans` | Every scan job: target, status, progress, result counts, timestamps |
| `vulnerabilities` | Every vulnerability found by any scan (linked to a scan) |
| `cve_entries` | Known CVE database entries (separate from scan findings) |
| `chat_messages` | Every message in every AI chat session |
| `favorite_targets` | Targets you've saved to your favorites list |

---

### `backend/models/schemas.py` — The Data Shapes 📋
> **ELI5:** Like official forms. When the frontend sends data to the backend (or vice versa), it must match these exact shapes — right fields, right types. Pydantic validates everything automatically.

**Key schemas and what they shape:**
- `ScanRequest` → `{ "target": "example.com", "scanners": ["nmap", "nuclei"] }`
- `ScanResponse` → Full scan info including status, progress, counts
- `VulnerabilityResponse` → Full vulnerability data including CVE ID, severity, solution
- `ChatRequest` → `{ "message": "What is Log4Shell?", "session_id": "abc123" }`
- `ChatResponse` → `{ "answer": "...", "sources": [...], "session_id": "abc123" }`
- `AttackPath` → A chain of nodes and edges representing an attack route
- `DashboardStats` → Aggregate statistics for the main dashboard
- `EvalResult` → Evaluation metric name + score + detail breakdown

---

## 🖥️ FRONTEND — The Website

The frontend is a **React** web app built with **Vite**. It's the visual dashboard you see in your browser. It's entirely separate from the backend and communicates with it via API calls.

```
frontend/
├── index.html           ← The HTML skeleton (single page)
├── package.json         ← Node.js dependencies list
├── vite.config.js       ← Build tool config (proxies /api → backend)
├── tailwind.config.js   ← CSS design system config
│
└── 📁 src/
    ├── main.jsx         ← React app entry point (mounts to index.html)
    ├── App.jsx          ← Main router (which page shows for which URL)
    ├── index.css        ← Global styles (dark theme, fonts, etc.)
    │
    ├── 📁 api/
    │   └── client.js    ← All API calls in one place
    │
    ├── 📁 utils/
    │   └── sanitize.js  ← Cleans user input before display
    │
    ├── 📁 pages/        ← Full pages (each is a different screen)
    │   ├── Dashboard.jsx      ← Home screen with stats and recent scans
    │   ├── ScanConsole.jsx    ← The main scanning interface
    │   ├── RAGAssistant.jsx   ← AI chat interface
    │   ├── CVEBrowse.jsx      ← Browse the CVE knowledge base
    │   ├── CVEDetail.jsx      ← Details page for a single CVE
    │   └── Settings.jsx       ← App settings + backend log viewer
    │
    └── 📁 components/   ← Reusable UI building blocks
        ├── Layout.jsx          ← Outer shell (sidebar + main area)
        ├── Sidebar.jsx         ← Navigation menu on the left
        ├── ScanForm.jsx        ← The form to start a new scan
        ├── ScanResults.jsx     ← Table/list of scan findings
        ├── VulnerabilityCard.jsx ← One vulnerability displayed as a card
        ├── AttackPathGraph.jsx ← Visual graph of attack paths
        ├── ChatPanel.jsx       ← The AI chat message window
        ├── MetricsPanel.jsx    ← Stats numbers (total scans, vulns, etc.)
        └── ErrorBoundary.jsx   ← Catches crashes and shows a friendly message
```

---

### `frontend/src/main.jsx` — The Ignition Key 🔑
> **ELI5:** The very first JavaScript file that runs. It just mounts the React app onto the `<div id="root">` in the HTML file. One line is the most important: `ReactDOM.createRoot(…).render(<App />)`

---

### `frontend/src/App.jsx` — The Traffic Director 🚦
> **ELI5:** A map of the website. Tells React: "when the URL is `/scans`, show the ScanConsole page. When the URL is `/rag`, show the AI assistant page." Also manages the dark/light theme and saves it in your browser.

**Page routes:**
| URL | Page Shown |
|---|---|
| `/` | Dashboard |
| `/scans` | Scan Console |
| `/rag` | AI Chat (RAG Assistant) |
| `/cve` | CVE Browse |
| `/cve/:id` | CVE Detail for one specific CVE |
| `/settings` | Settings Page |
| `/*` (anything else) | 404 Not Found page |

---

### `frontend/src/api/client.js` — The Message Carrier 📮
> **ELI5:** Every time the website needs to talk to the backend (fetch data, start a scan, send a chat message), it uses functions defined here. It uses **Axios**, which is a library that makes sending network requests easy.

**Error handling built in:**
- HTTP 429 (Too Many Requests) → shows "please slow down" message
- Backend down → shows "cannot connect to server" message

---

### `frontend/src/utils/sanitize.js` — The Safety Filter 🛡️
> **ELI5:** Before showing any text from the internet on screen, this runs it through a cleaner to make sure it can't contain hidden HTML tricks (like malicious scripts). Prevents XSS attacks.

---

## 📄 Pages in Detail

### `Dashboard.jsx` — The Home Screen 🏠
> **ELI5:** Like the main screen of a security app — shows you big numbers at the top (total scans run, total vulnerabilities found, avg danger score) and a list of recent scans with their status. Click any scan to see details.

**What it fetches on load:** `/api/stats` for totals, `/api/scans` for the recent scan list.

---

### `ScanConsole.jsx` — The Scanning Workspace 🖥️
> **ELI5:** The main working area. Has the scan form (type a URL, pick scanners, hit "Start Scan"), a live progress bar that updates every 2 seconds, and once the scan is done, shows all the vulnerabilities found plus the attack path graph.

**Live updates:** Polls the backend every 2 seconds while a scan is running. Stops polling when scan reaches "completed" or "failed".

---

### `RAGAssistant.jsx` — The AI Ask-Me-Anything Page 💬
> **ELI5:** A chat window where you type questions like "How do I fix CVE-2021-44228?" and the AI answers based on the vulnerability database. Shows source references so you know where the answer came from.

---

### `CVEBrowse.jsx` — The Vulnerability Library 📖
> **ELI5:** Like a library catalog for security bugs. Search by keyword, filter by severity or "has known exploit". Click any result to go to its detail page.

---

### `CVEDetail.jsx` — One CVE Deep-Dive 🔍
> **ELI5:** The full profile page for a single CVE — like a Wikipedia article about one specific security bug. Shows the CVSS score, severity badge, what it affects, how to fix it, and external reference links.

---

### `Settings.jsx` — Settings & Logs ⚙️
> **ELI5:** The settings page with two sections:
> 1. **Settings info:** Shows backend URL, which AI model is configured, current version
> 2. **Backend Log Viewer:** Live window showing the last 500 lines of `backend.log` — useful for debugging when something goes wrong

---

## 🧩 Components in Detail

### `Layout.jsx` — The Page Shell 🖼️
> **ELI5:** The permanent outer frame of the app — the sidebar on the left and a content area on the right. Every page is "inside" the Layout. Also has the dark/light theme toggle button.

### `Sidebar.jsx` — The Navigation Menu 📋
> **ELI5:** The left-side navigation links (Dashboard, Scan Console, AI Assistant, CVE Browser, Settings). Highlights the current page so you always know where you are.

### `ScanForm.jsx` — The Scan Input Form 📝
> **ELI5:** The form where you type the website address to scan (e.g., `scanme.nmap.org`), tick which scanners to use (Nmap, Nuclei), and click "Start Scan". Has basic client-side validation to catch obvious mistakes before sending to the backend.

### `ScanResults.jsx` — The Findings Table 📊
> **ELI5:** A sortable table listing all the vulnerabilities found in a scan. Color-coded by severity (red=critical, orange=high, yellow=medium, blue=low). Shows the CVE ID, CVSS score, affected host/port, and whether an exploit is publicly known.

### `VulnerabilityCard.jsx` — One Vulnerability Display Card 🃏
> **ELI5:** An expandable card showing all details of one vulnerability: the description, which host and port it affects, the solution/fix, reference links, and a severity badge.

### `AttackPathGraph.jsx` — The Attack Flow Diagram 🗺️
> **ELI5:** A visual graph that draws the attack path — boxes for hosts, services, and vulnerabilities connected by arrows. Makes it visually clear how an attacker could chain vulnerabilities to move from one part of the system to another.

### `ChatPanel.jsx` — The Chat Message Window 💬
> **ELI5:** Displays the conversation between you and the AI. Your messages appear on the right, AI messages on the left (chat-bubble style). Shows small "source" chips below AI answers so you can see which CVEs the answer was based on.

### `MetricsPanel.jsx` — The Stats Dashboard Panel 📈
> **ELI5:** The top bar of the dashboard showing big numbers like "Total Scans: 12", "Critical: 3", "Average CVSS: 7.4". Color-coded for quick scanning.

### `ErrorBoundary.jsx` — The Crash Catcher 🪤
> **ELI5:** React's version of a safety net. If any component crashes (throws an unexpected error), instead of the whole page going blank, this component catches the crash and displays a friendly "Something went wrong" message with a Retry button.

---

## 🔧 Scripts — One-Time Helper Tools

```
scripts/
├── seed_cve_data.py   ← Loads CVE data into the AI's memory database
└── run_eval.py        ← Runs evaluation tests on the AI's answer quality
```

### `scripts/seed_cve_data.py` — The Knowledge Feeder 🌱
> **ELI5:** Before the AI can answer questions, it needs to "eat" some knowledge. This script reads a list of known CVEs and loads them into ChromaDB (the AI's searchable memory). Think of it as uploading a textbook into the AI's brain.

### `scripts/run_eval.py` — The Test Runner 🧪
> **ELI5:** Runs a batch of test questions with known correct answers through the AI, then calculates grades (precision, BLEU, ROUGE) to see how well the AI performs. Like a final exam for the AI.

---

## 🔄 Complete Workflow — What Happens When You Run a Scan

```
STEP 1: You double-click "Run_VulnDetect.bat"
         │
         ▼
         Backend starts on port 8000
         Frontend starts on port 5173
         Browser opens to http://localhost:5173

STEP 2: You go to "Scan Console" and type a domain
         e.g.: scanme.nmap.org
         Select: [✓] Nmap  [✓] Nuclei
         Click: [Start Scan]
         │
         ▼
         Frontend → POST /api/scans → Backend

STEP 3: Backend validates the target
         (Is it a real public IP/domain? Not localhost?)
         │
         ▼
         Creates a Scan record in SQLite (status: "pending")
         Launches scan in a background thread
         Returns scan ID immediately to frontend

STEP 4: Frontend polls every 2 seconds
         GET /api/scans/{id}
         Shows: "Running Nmap... 40% complete"
         │
         ▼ (background)
         Nmap runs → finds CVEs → returns list
         Nuclei runs → finds web vulns → returns list

STEP 5: Aggregator combines results
         Removes duplicates
         Normalizes severity labels
         Saves all vulnerabilities to database

STEP 6: Scan marked "completed"
         Stats calculated (Critical: 2, High: 5, etc.)
         │
         ▼
         Frontend poll detects "completed"
         Stops polling
         Fetches: GET /api/scans/{id}/results
         Fetches: GET /api/scans/{id}/attack-paths
         Displays: vulnerability table + attack path graph

STEP 7 (optional): You ask the AI a question
         e.g.: "How do I fix CVE-2021-44228?"
         │
         ▼
         Frontend → POST /api/rag/chat
         RAG Engine searches ChromaDB for similar CVEs
         Finds top 5 matching entries
         (With local LLM) → Ollama qwen2.5-coder:7b generates answer
         (Without local LLM) → Structured list returned
         Answer displayed in chat window with sources
```

---

## 🔄 Complete Workflow — What Happens When You Search CVEs

```
STEP 1: Go to "CVE Browser"
         Type a keyword: "apache"
         Select severity: "CRITICAL"
         │
         ▼
         Frontend → GET /api/cve?q=apache&severity=CRITICAL

STEP 2: Backend searches SQLite database
         Filters by description containing "apache"
         Filters where severity = "CRITICAL"
         Orders by CVSS score descending
         │
         ▼
         Returns list of matching CVEs

STEP 3: Click on a CVE
         Frontend → GET /api/cve/CVE-2021-41773
         │
         ▼
         Shows full detail page:
         - Description
         - CVSS Score + Severity badge
         - Solution/Fix instructions
         - Reference links
```

---

## 📊 Data Flow Diagram (Full System)

```
[USER BROWSER]
     │
     │ HTTP requests
     ▼
[React Frontend - Port 5173]
     │
     │ /api/* proxy → Port 8000
     ▼
[FastAPI Backend - Port 8000]
     ├─── GET /api/health       ──► Check scanner availability
     ├─── POST /api/scans       ──► [Orchestrator]
     │                                   │
     │                                   ├──► [NmapScanner] 
     │                                   │       │ runs nmap binary
     │                                   │       └──► XML parse → ScanVulnerability[]
     │                                   │
     │                                   ├──► [NucleiScanner]
     │                                   │       │ runs nuclei binary  
     │                                   │       └──► JSON parse → ScanVulnerability[]
     │                                   │
     │                                   └──► [Aggregator]
     │                                           │ deduplicate & save
     │                                           ▼
     │                                     [SQLite DB]
     │                                     vulndetect.db
     │
     ├─── GET /api/scans/{id}/attack-paths ──► [AttackPathService]
     │                                           │ networkx graph
     │                                           └──► AttackPath[]
     │
     ├─── POST /api/rag/chat   ──► [RAGEngine]
     │                               │
     │                               ├──► [ChromaDB] vector search
     │                               │       (all-MiniLM-L6-v2 embeddings)
     │                               │
     │                               └──► [Ollama qwen2.5-coder:7b] (local LLM)
     │                                   or fallback structured list
     │
     └─── GET /api/cve         ──► [SQLite DB] cve_entries table
```

---

## 🎯 Technology Glossary (Key Terms)

| Term | Simple Explanation |
|---|---|
| **FastAPI** | A Python library for building web APIs quickly |
| **SQLite** | A simple file-based database — no server needed |
| **SQLAlchemy** | Python library that makes talking to databases easy |
| **ChromaDB** | A special database that stores text as numbers (vectors) for AI search |
| **LangChain** | A toolkit for building AI applications |
| **Pydantic** | Python library that validates data shapes automatically |
| **React** | JavaScript library for building interactive websites |
| **Vite** | A modern, fast build tool for React apps |
| **Tailwind CSS** | A CSS framework for styling with classes |
| **Axios** | JavaScript library that makes HTTP requests easy |
| **CVE** | Common Vulnerabilities and Exposures — unique IDs for security bugs |
| **CVSS** | Common Vulnerability Scoring System — a 0-10 danger score |
| **RAG** | Retrieval-Augmented Generation — AI that looks up info before answering |
| **nmap** | A free tool that scans network ports and detects services |
| **Nuclei** | A fast web vulnerability scanner with 3000+ templates |
| **CORS** | Cross-Origin Resource Sharing — security rule for which sites can talk to which |
| **Rate Limiting** | Blocking users who send too many requests too fast (anti-abuse) |
| **Vector Embedding** | Converting text to numbers so an AI can find "similar meaning" |
| **Attack Path** | A chain of vulnerabilities an attacker could exploit in sequence |
| **BLEU/ROUGE** | Standard scores that measure how good a text answer is |

---

*Generated automatically from the VulnDetectRAG v2.0 source code.*

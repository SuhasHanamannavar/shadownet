# MIRAGE - Morphing Intelligent Real-time Adaptive Grid Engine

MIRAGE is an advanced, AI-driven adaptive cybersecurity honeypot system. It lures attackers, classifies their behavior in real-time using OpenAI, dynamically alters its operating persona, and captures comprehensive intelligence.

## 🚀 One-Command Setup

Run the entire MIRAGE stack (Cowrie Honeypot, FastAPI Orchestration, Dashboard) using Docker Compose:

```bash
docker-compose up --build -d
```

Ensure you have your OpenAI API key set in your environment:
```bash
export OPENAI_API_KEY="your-api-key"
```

## 📊 Accessing the Dashboard

Once the stack is running, the real-time Leaflet.js and Chart.js dashboard is available at:
**http://localhost:3000**

## 🎯 Triggering a Demo Attack

Judges love action! To simulate an attack locally and see the dashboard light up immediately:

**Option 1: From the Dashboard**
Click the "Trigger Demo Attack" button in the top right corner of the dashboard.

**Option 2: Via API**
```bash
curl -X POST http://localhost:8000/api/demo
```

**Option 3: Realistic SSH Simulation Script**
Run the included simulation script which uses `paramiko` to perform an actual attack sequence against the Cowrie container:
```bash
python simulate_attack.py
```

## 📄 Generating Attacker Reports

MIRAGE can automatically generate a beautiful PDF report for any captured session, including IP, Geo-location, commands executed, AI classification, and an AI-generated behavioral summary paragraph.

To download a report for a specific session:
```
http://localhost:8000/api/sessions/<SESSION_ID>/report
```
*(Replace `<SESSION_ID>` with an ID from the dashboard or SQLite database).*

## 🏗️ Architecture Stack

- **Honeypot:** Cowrie (Dockerized), HTTP, FTP (pyftpdlib)
- **Backend:** FastAPI + Uvicorn
- **Storage:** SQLite
- **AI Engine:** OpenAI GPT-4o
- **Frontend:** HTML, TailwindCSS, Leaflet.js, Chart.js
- **Reporting:** ReportLab

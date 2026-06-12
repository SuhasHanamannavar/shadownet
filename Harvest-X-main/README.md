<div align="center">
  <h1>🛡️ HarvestX</h1>
  <h3>Adaptive AI Honeypot & Threat Intelligence Dashboard</h3>
  <p>An intelligent, ML-driven cybersecurity honeypot that deceives, detects, and classifies attackers in real-time.</p>
</div>

---

## 🌐 Live Demo Links

**🔗 Fake Login / Gateway Portal (Trap System)**  
👉 [https://3a07858cb20bedc1-152-57-103-142.serveousercontent.com/static/login.html](https://3a07858cb20bedc1-152-57-103-142.serveousercontent.com/static/login.html)  
*(Note: Any login attempt triggers attack logging and redirects the user into the honeypot's fake terminal.)*

**🔗 Threat Intelligence Dashboard**  
👉 [https://a87d38c6b814dc16-152-57-103-142.serveousercontent.com](https://a87d38c6b814dc16-152-57-103-142.serveousercontent.com)  
*(Note: View real-time attacker behavior, ML classifications, and geographical threat tracking.)*

---

## ❌ Why Traditional Solutions Fail

Traditional honeypots and intrusion detection systems have several fundamental flaws:
- **Static Signatures:** Traditional honeypots are static and easily detected by modern scanners.
- **No Behavioral Intelligence:** They lack the ability to adapt to attacker behavior dynamically.
- **Zero Real-Time Adaptation:** They cannot change personas (e.g., from an IoT device to an Enterprise Server) on the fly.
- **Limited Analysis:** Logging is often rudimentary, providing IP addresses but failing to analyze the *intent* or *sophistication* of the attack.
- **No Attacker Classification:** They cannot reliably distinguish between automated bots, script kiddies, and Advanced Persistent Threats (APTs).

---

## ✅ The HarvestX Solution

HarvestX solves these issues by acting as a highly adaptive, AI-powered deception system. 

- **AI-Based Attacker Classification:** Utilizes a Random Forest ML model to instantly classify attackers based on payload behavior.
- **Adaptive System Personas:** Dynamically shifts its appearance (Linux terminal, Corporate Dashboard, etc.) to match what the attacker is probing for.
- **Real-Time Logging:** Every keystroke, command, and web request is securely captured and stored in MongoDB.
- **ML Integration:** Trained on the renowned UNSW-NB15 cybersecurity dataset for high-accuracy threat detection.
- **Fake Login Trap System:** A completely realistic, but entirely fake, enterprise login portal that captures credentials and traps the attacker in a sandbox.
- **Threat Intelligence Dashboard:** A sleek, live monitoring panel that provides actionable security insights to network defenders.

---

## 🎯 Key Features

- **Adaptive AI Honeypot**
- **Real-time Threat Dashboard**
- **ML-based Classification**
- **MongoDB Logging**
- **Fake Login Trap**
- **Attacker Simulation**

---

## 🧠 Core Architecture & Features

### 🖥 Frontend Interfaces (The Trap & The Monitor)
HarvestX employs highly realistic UIs designed specifically to deceive attackers and empower defenders:
- **Fake Login Page:** Simulates an enterprise Single Sign-On (SSO) portal. 
- **Admin Dashboard UI:** A fake corporate intranet that attackers "break into," complete with dummy user databases and settings.
- **Honeypot Terminal Simulation:** A web-based shell that fakes a Linux environment, capturing commands while returning realistic errors.
- **Real-Time Monitoring Interface:** The Threat Intelligence dashboard used by Blue Teams to watch the attacks happen live.

### ⚙️ Backend Systems
- **HoneypotAI Class:** The core orchestration engine managing the honeypot's state.
- **AttackerClassifier:** The ML inference engine evaluating payloads.
- **ResponseEngine:** Dynamically generates realistic fake terminal outputs and HTTP responses based on the attacker's actions.
- **MongoDB Integration:** High-speed, NoSQL storage for semi-structured attack logs.
- **Session Tracking System:** Implements "Sticky Sessions" to ensure once an attacker is flagged, they remain trapped in the honeypot environment.

### 📊 Threat Intelligence Dashboard
The dashboard serves as the central nervous system for security analysts:
- **Active Threats & Unique IPs:** Tracks concurrent attacker sessions and their origins.
- **Command Logs:** A live scroll of every terminal command attempted by trapped users.
- **Threat Level Indicator:** Dynamically adjusts the system's defensive posture based on current attack volume.
- **Attacker Classification:** Visualizes the breakdown of threats (Bots vs. Humans vs. APTs).
- **Geo-IP Map:** Plots the geographical origin of attacks on an interactive Leaflet.js map.

### 🤖 Machine Learning 
- **Dataset:** UNSW-NB15 (Comprehensive network intrusion dataset)
- **Features Extracted:** `dur` (duration), `spkts` (source packets), `sbytes` (source bytes), `rate`, payload length, SQLi/XSS heuristics.
- **Model:** Random Forest Classifier (`model.pkl`)
- **Purpose:** To classify whether a session is benign, exploratory (Human), automated (Bot), or highly sophisticated (APT).

### 🔗 Smart Contract Integration (Concept)
To ensure the absolute integrity of the gathered threat intelligence, HarvestX introduces a blockchain-based logging mechanism.
- **Immutable Attack Logs:** Ensures that sophisticated attackers who might theoretically break out of the sandbox cannot delete their tracks.
- **Tamper-Proof Storage:** Threat data is hashed and stored on a decentralized ledger.
- **Core Functions:** 
  - `logAttack()`: Commits a hashed attack signature to the chain.
  - `getAttackHistory()`: Retrieves the verified timeline.
  - `verifyIntegrity()`: Cross-checks MongoDB logs against the blockchain hashes.

---

## 🚀 How It Works (Step-by-Step)

1. **The Bait:** An attacker discovers the fake login portal and attempts to brute-force or inject SQL.
2. **The Capture:** The request is captured; the ML `AttackerClassifier` instantly flags the malicious payload.
3. **The Trap:** The attacker is seamlessly redirected to the fake Admin Dashboard or Terminal Simulation via a "sticky session".
4. **The Engagement:** The `ResponseEngine` processes their commands, serving them fake files and errors to keep them engaged.
5. **The Storage:** Every action is permanently stored in MongoDB (and optionally hashed to the Smart Contract).
6. **The Intelligence:** The Threat Intelligence Dashboard updates in real-time, alerting security teams.

---

## 📸 Project Gallery

*(Placeholder for Screenshots)*
- **Threat Intelligence Dashboard**
- **HarvestX Enterprise Portal (Fake Login)**
- **CorpNet Admin Dashboard (Trap Terminal)**

---

## 🧰 Tech Stack

**Frontend:**
- HTML5, CSS3, Vanilla JavaScript, Leaflet.js

**Backend:**
- Python 3.11, FastAPI, Flask, WebSockets (Socket.IO)

**Database:**
- MongoDB, SQLite

**Machine Learning:**
- Scikit-learn, Pandas, Joblib

**Infrastructure & Tools:**
- Docker & Docker Compose
- Cowrie (SSH/Telnet Emulation)

---

## 📦 Installation & Setup

**1. Clone the repository:**
```bash
git clone https://github.com/yourusername/harvestX.git
cd harvestX
```

**2. Install Python dependencies:**
```bash
pip install -r requirements.txt
```

**3. Run MongoDB (Ensure MongoDB is installed locally or update URI):**
```bash
mongod
```

**4. Train the ML Model (Optional - requires dataset):**
```bash
python train_model.py
```

**5. Start the Honeypot Backend & Dashboards:**
```bash
# To run via Python scripts
cd MIRAGE
python main.py

# OR: Deploy using Docker Compose (Recommended)
docker-compose up -d --build
```

---

## 📌 Use Cases

- **Cybersecurity Research:** Gather modern malware signatures and zero-day exploit patterns.
- **Threat Intelligence Systems:** Feed verified attacker IPs and tactics into corporate firewalls.
- **Enterprise Security Monitoring:** Serve as an early-warning tripwire inside corporate networks.
- **Red Team / Blue Team Exercises:** Provide a safe, realistic environment for attack simulation and defense training.

---

## 🌍 Impact

HarvestX transforms passive defense into active engagement. By deceiving attackers, it wastes their time and resources while providing Blue Teams with **early detection**, **real-time visibility**, and **actionable threat intelligence** to fortify their actual networks.

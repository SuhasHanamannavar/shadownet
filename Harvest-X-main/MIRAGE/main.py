import os
import threading
import sqlite3
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from http.server import HTTPServer, SimpleHTTPRequestHandler
import uvicorn
import pydantic
from pydantic import BaseModel

import config
from modules import log_watcher, breadcrumbs

app = FastAPI(title="MIRAGE Orchestration API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class WebEvent(BaseModel):
    session_id: str
    src_ip: str
    action: str
    attack_type: str = "WEB_ATTACKER"
    confidence: float = 0.95

class RRWebEvent(BaseModel):
    session_id: str
    events: list

@app.post("/api/rrweb")
async def handle_rrweb(req: RRWebEvent):
    for client in list(connected_clients):
        try:
            await client.send_json({"type": "rrweb", "session_id": req.session_id, "events": req.events})
        except Exception:
            connected_clients.remove(client)
    return {"status": "ok"}

# Active websocket connections
connected_clients = []

def init_db():
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            src_ip TEXT,
            attacker_type TEXT,
            confidence REAL,
            reasoning TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            command TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def start_ftp_honeypot():
    try:
        authorizer = DummyAuthorizer()
        authorizer.add_user("admin", "12345", ".", perm="elr")
        authorizer.add_anonymous(".")
        handler = FTPHandler
        handler.authorizer = authorizer
        server = FTPServer(("0.0.0.0", config.PORTS["ftp"]), handler)
        print(f"[FTP Honeypot] Started on port {config.PORTS['ftp']}")
        server.serve_forever()
    except Exception as e:
        print(f"[FTP Honeypot] Error: {e}")

def start_http_honeypot():
    try:
        server_address = ('0.0.0.0', config.PORTS["http"])
        httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
        print(f"[HTTP Honeypot] Started on port {config.PORTS['http']}")
        httpd.serve_forever()
    except Exception as e:
        print(f"[HTTP Honeypot] Error: {e}")

async def broadcast_event(event_data: dict):
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_json(event_data)
        except Exception:
            disconnected.append(client)
    for client in disconnected:
        connected_clients.remove(client)

@app.on_event("startup")
async def startup_event():
    print(r"""
    __  ___   ____   ____     ___    ______   ______
   /  |/  /  /  _/  / __ \   /   |  / ____/  / ____/
  / /|_/ /   / /   / /_/ /  / /| | / / __   / __/   
 / /  / /  _/ /   / _, _/  / ___ |/ /_/ /  / /___   
/_/  /_/  /___/  /_/ |_|  /_/  |_|\____/  /_____/   
    Adaptive Multi-OS Honeypot Engine
    """)
    init_db()
    
    # Initialize cowrie logs dir
    os.makedirs(os.path.dirname(config.COWRIE_LOG_PATH), exist_ok=True)
    if not os.path.exists(config.COWRIE_LOG_PATH):
        with open(config.COWRIE_LOG_PATH, 'a'): pass
        
    breadcrumbs.plant()
    
    # Start log watcher in background thread
    # We pass the asyncio event loop and broadcast function so the watcher can send ws messages
    loop = asyncio.get_event_loop()
    def watcher_callback(event):
        asyncio.run_coroutine_threadsafe(broadcast_event(event), loop)
        
    threading.Thread(target=log_watcher.start, args=(watcher_callback,), daemon=True).start()
    threading.Thread(target=start_ftp_honeypot, daemon=True).start()
    threading.Thread(target=start_http_honeypot, daemon=True).start()

@app.get("/")
def read_root():
    return {"status": "MIRAGE Backend Running"}

@app.get("/api/live-sessions")
def get_live_sessions():
    from modules.live_session import get_all_sessions
    return get_all_sessions()

@app.get("/api/sessions")
def get_sessions():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions ORDER BY timestamp ASC LIMIT 50")
    db_sessions = cursor.fetchall()
    
    sessions_dict = {}
    for row in db_sessions:
        sid = row["session_id"]
        c_type = row["attacker_type"]
        # Map new backend types to old ML classes to avoid breaking UI
        if c_type == "APT": c_class = "ADVANCED_THREAT"
        elif c_type == "Bot": c_class = "AUTOMATED_BOT"
        elif c_type == "Script Kiddie": c_class = "EXPLORATORY"
        else: c_class = "UNKNOWN"
        
        cursor.execute("SELECT command FROM commands WHERE session_id=?", (sid,))
        cmds = [c[0] for c in cursor.fetchall()]
        
        sessions_dict[sid] = {
            "src_ip": row["src_ip"],
            "start_time": row["timestamp"].replace(" ", "T"),
            "commands": cmds,
            "classification": c_class,
            "risk_score": int((row["confidence"] or 0) * 100)
        }
        
    conn.close()
    return sessions_dict

@app.get("/api/system/os")
def get_os():
    return {"current_os": "Linux (Ubuntu 22.04)"}

@app.get("/api/stats")
def get_stats():
    conn = sqlite3.connect(config.DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM sessions")
    total_sessions = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM commands")
    total_cmds = cursor.fetchone()[0]
    conn.close()
    return {"total_sessions": total_sessions, "total_commands": total_cmds}

@app.get("/api/demo")
@app.post("/api/demo")
async def trigger_demo():
    event = {
        "eventid": "cowrie.session.demo",
        "src_ip": "1.2.3.4",
        "session": "demo-session-id",
        "message": "Demo attack triggered"
    }
    await broadcast_event(event)
    return {"status": "demo triggered"}

@app.post("/api/web-event")
def handle_web_event(event: WebEvent):
    from modules import live_session as ls
    
    # Send directly to the live terminal
    ls.command_executed(event.session_id, event.src_ip, f"[WEB] {event.action}")
    
    # Classify immediately
    classification = {
        "type": event.attack_type,
        "confidence": event.confidence,
        "reasoning": "Detected by Flask ML Gateway"
    }
    ls.session_classified(event.session_id, classification)
    
    # Store in MIRAGE DB for map history
    try:
        conn = sqlite3.connect(config.DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT OR IGNORE INTO sessions (session_id, src_ip, attacker_type, confidence, reasoning)
                     VALUES (?, ?, ?, ?, ?)''', 
                  (event.session_id, event.src_ip, event.attack_type, event.confidence, classification["reasoning"]))
        c.execute("INSERT INTO commands (session_id, command) VALUES (?, ?)", (event.session_id, f"[WEB] {event.action}"))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Web Event DB Error: {e}")
        
    return {"status": "ok"}

@app.websocket("/ws/feed")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_clients.remove(websocket)

@app.get("/api/sessions/{session_id}/report")
def generate_report_endpoint(session_id: str):
    from modules import reporter
    pdf_path = reporter.generate_report(session_id)
    if pdf_path:
        from fastapi.responses import FileResponse
        return FileResponse(pdf_path, filename=f"report_{session_id}.pdf")
    return {"error": "Failed to generate report"}

class ClassifyRequest(pydantic.BaseModel):
    commands: list
    timings: list = []
    src_ip: str = "unknown"

@app.post("/api/classify")
def classify_session(req: ClassifyRequest):
    """Live ML classification endpoint for the test UI."""
    try:
        from modules.classifier import classify
        from modules.feature_extractor import extract

        session_data = {
            "commands": req.commands,
            "timings":  req.timings if req.timings else [1.0] * len(req.commands),
            "src_ip":   req.src_ip,
        }
        result = classify(session_data)

        # Also return the raw feature vector for the UI breakdown
        features_raw = extract(session_data)
        feature_names = [
            "recon%","download%","exec%","lateral%","destruct%","auth%","misc%",
            "total_cmds","unique_cmds","entropy","max_cmd_len","mean_cmd_len",
            "mean_gap","std_gap","min_gap","max_gap","burst_ratio",
            "has_sudo","has_privesc","has_pyexec","has_encoded","has_redirect",
        ]
        features = dict(zip(feature_names, [round(f, 3) for f in features_raw]))

        return {
            "classification": result,
            "features": features,
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/test")
def test_ui():
    from fastapi.responses import HTMLResponse
    try:
        with open("static/test.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h2>Test UI not found.</h2>")

@app.get("/monitor")
def monitor_ui():
    from fastapi.responses import HTMLResponse
    try:
        with open("static/monitor.html", "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        return HTMLResponse("<h2>Monitor UI not found.</h2>")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
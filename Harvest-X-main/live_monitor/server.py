"""
ShadowNet Live Monitor Server — Port 6001
Real-time attacker session recording, WebSocket streaming, and REST API backed by MongoDB.
"""
import os
import json
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO
from flask_cors import CORS
from pymongo import MongoClient

BASE_DIR = os.path.dirname(__file__)

import sys
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)
from classifier import classify_session

app = Flask(__name__, static_folder=BASE_DIR)
app.config["SECRET_KEY"] = "mirage_live_2025"
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", logger=False, engineio_logger=False)

# ── MongoDB Client Setup ──────────────────────────────────────────────────────
# NEW MONGODB SECTION START
client = MongoClient("mongodb://localhost:27017")
db = client["shadownet_db"]
attacker_logs = db["attacker_logs"]
alerts = db["alerts"]
session_replays = db["session_replays"]

def init_db():
    # Setup indexes for high-speed queries
    attacker_logs.create_index("session_id", unique=True)
    attacker_logs.create_index("attacker_ip")
    attacker_logs.create_index("timestamp")
    
    alerts.create_index("timestamp")
    alerts.create_index("attacker_ip")
    
    session_replays.create_index("session_id", unique=True)
    print("[DB] MongoDB collections initialized and indexes created.")
# NEW MONGODB SECTION END


# ── Location Helper ───────────────────────────────────────────────────────────
def get_ip_location(ip):
    if not ip or ip == "Unknown":
        return "Unknown", "Unknown"
    if ip == "127.0.0.1" or ip.startswith("192.168."):
        return "United States", "San Francisco"
    countries = [
        ("United States", "New York"),
        ("Germany", "Frankfurt"),
        ("United Kingdom", "London"),
        ("China", "Shanghai"),
        ("Netherlands", "Amsterdam"),
        ("Russia", "St Petersburg"),
        ("Japan", "Osaka"),
        ("Canada", "Montreal"),
        ("France", "Marseille"),
        ("Brazil", "Rio de Janeiro")
    ]
    try:
        parts = ip.split('.')
        if len(parts) == 4:
            val = (int(parts[0]) + int(parts[1]) + int(parts[2])) % len(countries)
            return countries[val]
    except Exception:
        pass
    return "Unknown", "Unknown"


# ── API Document Mapping Helper ───────────────────────────────────────────────
def map_mongo_to_api(doc):
    if not doc:
        return None
    mapped = dict(doc)
    mapped.pop("_id", None)
    mapped["src_ip"] = doc.get("attacker_ip", "Unknown")
    mapped["start_time"] = doc.get("timestamp", "")
    mapped["attacker_type"] = doc.get("classification", "Scanner")
    mapped["risk_score"] = doc.get("threat_score", 50)
    mapped["interest"] = doc.get("current_interest", "Reconnaissance")
    mapped["latest_command"] = doc["commands"][-1]["command"] if doc.get("commands") else ""
    return mapped


# ── MongoDB Core Functions ────────────────────────────────────────────────────
# NEW MONGODB CORE FUNCTIONS START
def save_attack_event(data):
    session_id = data.get("session_id", "unknown")
    src_ip = data.get("src_ip", "Unknown")
    command = data.get("command", "")
    response = data.get("response", "")
    ts = data.get("timestamp", datetime.utcnow().isoformat())
    
    # Check if session exists
    sess = attacker_logs.find_one({"session_id": session_id})
    if not sess:
        country, city = get_ip_location(src_ip)
        sess = {
            "session_id": session_id,
            "timestamp": ts,
            "attacker_ip": src_ip,
            "country": country,
            "city": city,
            "classification": data.get("attacker_type", "Scanner"),
            "threat_level": "LOW",
            "threat_score": int(data.get("risk_score", 50)),
            "current_interest": "Reconnaissance",
            "commands": [],
            "command_count": 0,
            "session_duration": 0,
            "confidence": 50,
            "payload_download_detected": False,
            "login_attempts": 0,
            "status": "active"
        }
    
    # Process command if present
    if command:
        cmd_obj = {
            "time": ts,
            "command": command
        }
        # Check if this command was already recorded to avoid duplicates
        if cmd_obj not in sess["commands"]:
            sess["commands"].append(cmd_obj)
            
        cmd_lower = command.lower()
        if "wget" in cmd_lower or "curl" in cmd_lower:
            sess["payload_download_detected"] = True
            sess["current_interest"] = "Malware"
            
        if "username=" in command or "password=" in command:
            sess["login_attempts"] += 1
            sess["current_interest"] = "Credentials"
            
        if any(db_kw in cmd_lower for db_kw in ["mysql", "mongo", "sqlite"]):
            sess["current_interest"] = "Database"
            
    sess["command_count"] = len(sess["commands"])
    
    # Calculate duration
    try:
        start_t_str = sess["timestamp"].replace("Z", "+00:00")
        curr_t_str = ts.replace("Z", "+00:00")
        start_time = datetime.fromisoformat(start_t_str)
        curr_time = datetime.fromisoformat(curr_t_str)
        sess["session_duration"] = int((curr_time - start_time).total_seconds())
    except Exception:
        sess["session_duration"] = 0
        
    # Re-classify and get updated stats
    classification, confidence, threat_level, threat_score, interest = classify_session(
        [{"command": c["command"], "timestamp": c["time"]} for c in sess["commands"]]
    )
    
    # Merge values
    sess["classification"] = classification
    sess["confidence"] = confidence
    sess["threat_level"] = threat_level
    sess["threat_score"] = max(sess["threat_score"], threat_score)
    sess["current_interest"] = interest or sess["current_interest"]
    
    # Merge preset profile if passed in payload
    req_profile = data.get("attacker_profile")
    if req_profile:
        if req_profile.get("classification"):
            sess["classification"] = req_profile["classification"]
        if req_profile.get("confidence") is not None:
            sess["confidence"] = int(req_profile["confidence"])
        if req_profile.get("threat_score") is not None:
            sess["threat_score"] = max(sess["threat_score"], int(req_profile["threat_score"]))
        if req_profile.get("interest"):
            sess["current_interest"] = req_profile["interest"]
            
    # Upsert the session log
    attacker_logs.replace_one({"session_id": session_id}, sess, upsert=True)
    
    # Store session replay
    update_session_replay(session_id, sess["commands"], sess["session_duration"])
    
    return sess

def update_session(session_id, update_data):
    """Update fields in an active session log."""
    attacker_logs.update_one({"session_id": session_id}, {"$set": update_data})

def store_alert(alert_data):
    """Store alert details in database."""
    alerts.insert_one(alert_data)

def get_recent_sessions(limit=50):
    """Retrieve list of recent sessions."""
    return list(attacker_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))

def get_attacker_history(session_id):
    """Retrieve details of a specific session."""
    return attacker_logs.find_one({"session_id": session_id}, {"_id": 0})

def get_session_replay(session_id):
    """Retrieve session replay commands and metadata."""
    return session_replays.find_one({"session_id": session_id}, {"_id": 0})

def update_session_replay(session_id, commands, duration):
    """Update session replay commands and metadata."""
    replay = {
        "session_id": session_id,
        "commands": commands,
        "duration": duration
    }
    session_replays.replace_one({"session_id": session_id}, replay, upsert=True)
# NEW MONGODB CORE FUNCTIONS END


# ── REST API ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    """Serve any static file from the live_monitor directory."""
    return send_from_directory(BASE_DIR, filename)

@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    docs = get_recent_sessions(100)
    return jsonify([map_mongo_to_api(d) for d in docs])

@app.route("/api/live", methods=["GET"])
def live_sessions():
    docs = list(attacker_logs.find({"status": "active"}, {"_id": 0}).sort("timestamp", -1))
    return jsonify([map_mongo_to_api(d) for d in docs])

@app.route("/api/session/<session_id>", methods=["GET"])
def get_session(session_id):
    sess = get_attacker_history(session_id)
    if not sess:
        return jsonify({"error": "Not found"}), 404
    mapped = map_mongo_to_api(sess)
    
    # Match SQLite subcommand formatting for frontend compatibility
    cmds = []
    for c in sess.get("commands", []):
        cmds.append({
            "command": c.get("command", ""),
            "timestamp": c.get("time", ""),
            "response": ""
        })
    mapped["commands"] = cmds
    return jsonify(mapped)

@app.route("/api/export/<session_id>", methods=["GET"])
def export_session(session_id):
    data = get_session(session_id).get_json()
    resp = app.response_class(
        json.dumps(data, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=session_{session_id[:12]}.json"}
    )
    return resp

@app.route("/api/stats", methods=["GET"])
def stats():
    total = attacker_logs.count_documents({})
    active = attacker_logs.count_documents({"status": "active"})
    hi_risk = attacker_logs.count_documents({"threat_score": {"$gt": 80}})
    
    # Aggregated count of all executed commands
    pipeline = [{"$group": {"_id": None, "total": {"$sum": "$command_count"}}}]
    res = list(attacker_logs.aggregate(pipeline))
    cmds = res[0]["total"] if res else 0
    
    unique_ips = len(attacker_logs.distinct("attacker_ip"))
    
    bot_count = attacker_logs.count_documents({"classification": "Bot"})
    human_count = attacker_logs.count_documents({"classification": "Human"})
    apt_count = attacker_logs.count_documents({"classification": "APT"})
    scanner_count = attacker_logs.count_documents({"classification": "Scanner"})
    script_kiddie_count = attacker_logs.count_documents({"classification": "Script Kiddie"})
    
    return jsonify({
        "total": total,
        "active": active,
        "high_risk": hi_risk,
        "commands": cmds,
        "unique_ips": unique_ips,
        "bot_count": bot_count,
        "human_count": human_count,
        "apt_count": apt_count,
        "scanner_count": scanner_count,
        "script_kiddie_count": script_kiddie_count
    })

# ── Rebranding & MongoDB Required API Routes ──────────────────────────────────
@app.route("/api/attacks", methods=["GET"])
def get_attacks():
    sessions = get_recent_sessions(100)
    return jsonify([map_mongo_to_api(s) for s in sessions])

@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    limit = request.args.get("limit", 50, type=int)
    docs = list(alerts.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
    return jsonify(docs)

@app.route("/api/replays", methods=["GET"])
def get_replays():
    limit = request.args.get("limit", 50, type=int)
    docs = list(session_replays.find({}, {"_id": 0}).limit(limit))
    return jsonify(docs)


# ── Event Ingestion ───────────────────────────────────────────────────────────
@app.route("/api/ingest", methods=["POST"])
def ingest():
    """Receive events from the honeypot and save directly in MongoDB."""
    data = request.json or {}
    event_type = data.get("event_type", "command_executed")
    session_id = data.get("session_id", "unknown")
    src_ip = data.get("src_ip", "Unknown")
    command = data.get("command", "")
    response = data.get("response", "")
    ts = data.get("timestamp", datetime.utcnow().isoformat())

    # Check if session exists before saving
    is_new_session = attacker_logs.find_one({"session_id": session_id}) is None
    
    # Save the attack event to MongoDB
    sess_doc = save_attack_event(data)
    
    classification = sess_doc.get("classification", "Scanner")
    threat_score = sess_doc.get("threat_score", 50)
    
    # Broadcast session_start
    if is_new_session:
        socketio.emit("session_start", map_mongo_to_api(sess_doc))
        
    if command:
        # Broadcast command_executed
        payload = map_mongo_to_api(sess_doc)
        payload["command"] = command
        payload["response"] = response
        socketio.emit("command_executed", payload)
        
        # Store high threat alert in MongoDB alerts collection if threat score is high
        if threat_score > 80:
            alert_msg = f"HIGH RISK [{classification}] command from {src_ip}: {command[:80]}"
            alert_data = {
                "timestamp": ts,
                "attacker_ip": src_ip,
                "classification": classification,
                "threat_score": threat_score,
                "message": alert_msg
            }
            store_alert(alert_data)
            
            # Broadcast WebSocket alert
            socketio.emit("alert", {
                "session_id": session_id,
                "src_ip": src_ip,
                "message": alert_msg,
                "risk_score": threat_score,
                "timestamp": ts
            })
            
    if event_type == "session_end":
        update_session(session_id, {"status": "ended", "end_time": ts})
        socketio.emit("session_end", {"session_id": session_id, "timestamp": ts})
        
    return jsonify({"status": "ok"})


# ── WebSocket ─────────────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    print(f"[MONITOR] Dashboard client connected")

@socketio.on("disconnect")
def on_disconnect():
    print(f"[MONITOR] Dashboard client disconnected")

@socketio.on("subscribe")
def on_subscribe(data):
    session_id = data.get("session_id")
    print(f"[MONITOR] Client subscribed to session: {session_id}")


# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  ShadowNet Live Monitor (MongoDB-Backed)")
    print("  Dashboard : http://localhost:6001")
    print("  API       : http://localhost:6001/api/sessions")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=6001, debug=False, allow_unsafe_werkzeug=True)

"""
MIRAGE Live Monitor Server — Port 6001
Real-time attacker session recording, WebSocket streaming, and REST API.
"""
import os
import json
import sqlite3
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO
from flask_cors import CORS

BASE_DIR = os.path.dirname(__file__)
DB_PATH  = os.path.join(BASE_DIR, "monitor.db")

import sys
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)
from classifier import classify_session

app = Flask(__name__, static_folder=BASE_DIR)
app.config["SECRET_KEY"] = "mirage_live_2025"
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", logger=False, engineio_logger=False)

DANGEROUS_TOKENS = (
    "rm -rf", "mkfs", ":(){", "chmod 777", "chattr -i", "dd if=", ">/dev/sd",
    "wget ", "curl ", "nc ", "netcat", "bash -i", "/dev/tcp", "python -c",
    "perl -e", "base64 -d", "sshpass", "iptables -F", "crontab", "passwd",
    "shadow", "authorized_keys", "sudo ", "su -", "history -c"
)


def parse_ts(value):
    """Parse Cowrie/ISO timestamps without changing their stored representation."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def duration_seconds(start_time, end_time):
    start = parse_ts(start_time)
    end = parse_ts(end_time) or datetime.now(timezone.utc)
    if not start:
        return 0
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return max(0, int(round((end - start).total_seconds())))


def is_dangerous_command(command):
    cmd = (command or "").lower()
    return any(token in cmd for token in DANGEROUS_TOKENS)


def add_replay_timing(commands):
    previous_ts = None
    for idx, cmd in enumerate(commands):
        current_ts = parse_ts(cmd.get("timestamp"))
        if idx == 0 or not current_ts or not previous_ts:
            delay_ms = 0
        else:
            delay_ms = max(0, int(round((current_ts - previous_ts).total_seconds() * 1000)))
        cmd["replay_delay_ms"] = delay_ms
        cmd["is_dangerous"] = bool(cmd.get("is_dangerous")) or is_dangerous_command(cmd.get("command"))
        if current_ts:
            previous_ts = current_ts
    return commands


def enrich_session(row):
    data = dict(row)
    data["session_duration"] = data.get("session_duration") or duration_seconds(
        data.get("start_time"), data.get("end_time")
    )
    data["classification"] = data.get("attacker_type", "Unknown")
    data["threat_score"] = data.get("threat_score", data.get("risk_score", 0))
    return data


# ── Database ──────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS sessions (
        session_id   TEXT PRIMARY KEY,
        src_ip       TEXT,
        start_time   TEXT,
        end_time     TEXT,
        attacker_type TEXT DEFAULT 'Unknown',
        risk_score   INTEGER DEFAULT 50,
        status       TEXT DEFAULT 'active',
        command_count INTEGER DEFAULT 0,
        confidence   INTEGER DEFAULT 0,
        interest     TEXT DEFAULT 'None',
        threat_score INTEGER DEFAULT 0,
        latest_command TEXT DEFAULT '',
        session_duration INTEGER DEFAULT 0
    )""")
    
    # Safe alter table for existing database compatibility
    for col, type_ in [("confidence", "INTEGER DEFAULT 0"), 
                       ("interest", "TEXT DEFAULT 'None'"), 
                       ("threat_score", "INTEGER DEFAULT 0"), 
                       ("latest_command", "TEXT DEFAULT ''"),
                       ("session_duration", "INTEGER DEFAULT 0")]:
        try:
            c.execute(f"ALTER TABLE sessions ADD COLUMN {col} {type_}")
        except sqlite3.OperationalError:
            pass # Already exists
            
    c.execute("""CREATE TABLE IF NOT EXISTS commands (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id    TEXT,
        command       TEXT,
        response      TEXT,
        timestamp     TEXT,
        risk_score    INTEGER DEFAULT 50,
        attacker_type TEXT,
        response_time REAL DEFAULT 0,
        command_order INTEGER DEFAULT 0,
        is_dangerous  INTEGER DEFAULT 0
    )""")
    for col, type_ in [("command_order", "INTEGER DEFAULT 0"),
                       ("is_dangerous", "INTEGER DEFAULT 0")]:
        try:
            c.execute(f"ALTER TABLE commands ADD COLUMN {col} {type_}")
        except sqlite3.OperationalError:
            pass
    c.execute("CREATE INDEX IF NOT EXISTS idx_commands_session_order ON commands(session_id, command_order, timestamp, id)")
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ── REST API ──────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    """Serve any static file (logo.png, css, js, etc.) from the live_monitor directory."""
    return send_from_directory(BASE_DIR, filename)

@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM sessions ORDER BY start_time DESC"
    ).fetchall()
    conn.close()
    return jsonify([enrich_session(r) for r in rows])

@app.route("/api/recent_sessions", methods=["GET"])
def recent_sessions():
    """Completed Cowrie sessions available for replay."""
    conn = get_db()
    rows = conn.execute(
        """SELECT * FROM sessions
           WHERE status='ended'
           ORDER BY COALESCE(end_time, start_time) DESC
           LIMIT 25"""
    ).fetchall()
    conn.close()
    return jsonify([enrich_session(r) for r in rows])

@app.route("/api/live", methods=["GET"])
def live_sessions():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM sessions WHERE status='active' ORDER BY start_time DESC"
    ).fetchall()
    conn.close()
    return jsonify([enrich_session(r) for r in rows])

@app.route("/api/session/<session_id>", methods=["GET"])
def get_session(session_id):
    conn = get_db()
    sess = conn.execute(
        "SELECT * FROM sessions WHERE session_id=?", (session_id,)
    ).fetchone()
    if not sess:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    cmds = conn.execute(
        "SELECT * FROM commands WHERE session_id=? ORDER BY command_order, timestamp, id", (session_id,)
    ).fetchall()
    conn.close()
    result = enrich_session(sess)
    result["commands"] = add_replay_timing([dict(c) for c in cmds])
    return jsonify(result)

@app.route("/api/replay/<session_id>", methods=["GET"])
def replay_session(session_id):
    data, status = get_session(session_id), 200
    if data.status_code != 200:
        return data
    payload = data.get_json()
    if payload.get("status") != "ended":
        status = 409
        payload["error"] = "Replay is available after the Cowrie session ends."
    return jsonify(payload), status

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
    conn = get_db()
    total   = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    active  = conn.execute("SELECT COUNT(*) FROM sessions WHERE status='active'").fetchone()[0]
    hi_risk = conn.execute("SELECT COUNT(*) FROM sessions WHERE risk_score > 80").fetchone()[0]
    cmds    = conn.execute("SELECT COUNT(*) FROM commands").fetchone()[0]
    unique_ips = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM sessions").fetchone()[0]
    
    bot_count = conn.execute("SELECT COUNT(*) FROM sessions WHERE attacker_type = 'Bot'").fetchone()[0]
    human_count = conn.execute("SELECT COUNT(*) FROM sessions WHERE attacker_type = 'Human'").fetchone()[0]
    apt_count = conn.execute("SELECT COUNT(*) FROM sessions WHERE attacker_type = 'APT'").fetchone()[0]
    scanner_count = conn.execute("SELECT COUNT(*) FROM sessions WHERE attacker_type = 'Scanner'").fetchone()[0]
    script_kiddie_count = conn.execute("SELECT COUNT(*) FROM sessions WHERE attacker_type = 'Script Kiddie'").fetchone()[0]
    
    conn.close()
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

# ── Event Ingestion ───────────────────────────────────────────────────────────
@app.route("/api/ingest", methods=["POST"])
def ingest():
    """Receive events from the honeypot and broadcast via WebSocket."""
    data = request.json or {}
    event_type    = data.get("event_type", "command_executed")
    session_id    = data.get("session_id", "unknown")
    src_ip        = data.get("src_ip", "Unknown")
    command       = data.get("command", "")
    response      = data.get("response", "")
    attacker_type = data.get("attacker_type", "Scanner")
    risk_score    = int(data.get("risk_score", 50))
    response_time = float(data.get("response_time", 0))
    ts = data.get("timestamp", datetime.now(timezone.utc).isoformat())

    conn = get_db()

    # 1. Upsert session skeleton first to prevent UNIQUE constraint race conditions
    existing = conn.execute(
        "SELECT session_id FROM sessions WHERE session_id=?", (session_id,)
    ).fetchone()

    is_new_session = False
    if not existing:
        is_new_session = True
        conn.execute(
            """INSERT INTO sessions (session_id, src_ip, start_time, attacker_type, risk_score, status, command_count, confidence, interest, threat_score, latest_command)
               VALUES (?, ?, ?, ?, ?, 'active', 0, 50, 'Reconnaissance', ?, ?)""",
            (session_id, src_ip, ts, attacker_type, risk_score, risk_score, command)
        )
        conn.commit()

    # 2. Fetch all existing commands for classification
    cmds_rows = conn.execute(
        "SELECT command, timestamp FROM commands WHERE session_id=? ORDER BY command_order, timestamp, id", 
        (session_id,)
    ).fetchall()
    cmds_list = [{"command": r["command"], "timestamp": r["timestamp"]} for r in cmds_rows]

    # 3. Append current command in-memory for classification
    if command:
        cmds_list.append({"command": command, "timestamp": ts})

    # 4. Classify attacker behavior
    classification, confidence, threat_level, threat_score, interest = classify_session(cmds_list)

    # Override with preset profile if passed in payload (useful for web-specific download triggers)
    req_profile = data.get("attacker_profile")
    if req_profile:
        if req_profile.get("classification"):
            classification = req_profile["classification"]
        if req_profile.get("confidence") is not None:
            confidence = int(req_profile["confidence"])
        if req_profile.get("threat_score") is not None:
            threat_score = max(threat_score, int(req_profile["threat_score"]))
        if req_profile.get("interest"):
            interest = req_profile["interest"]

    # 5. Record command to database
    if command:
        next_order = conn.execute(
            "SELECT COALESCE(MAX(command_order), 0) + 1 FROM commands WHERE session_id=?",
            (session_id,)
        ).fetchone()[0]
        dangerous = 1 if is_dangerous_command(command) else 0
        conn.execute(
            """INSERT INTO commands (session_id, command, response, timestamp, risk_score, attacker_type, response_time, command_order, is_dangerous)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, command, response, ts, risk_score, attacker_type, response_time, next_order, dangerous)
        )
        conn.commit()

    # 6. Update session metadata and classification
    conn.execute(
        """UPDATE sessions SET command_count = ?,
           risk_score = MAX(risk_score, ?), status='active',
           attacker_type = ?, confidence = ?, interest = ?,
           threat_score = ?, latest_command = ?
           WHERE session_id=?""",
        (len(cmds_list), threat_score, classification, confidence, interest, threat_score, command, session_id)
    )
    conn.commit()

    # 7. Broadcast WebSocket events
    if is_new_session:
        socketio.emit("session_start", {
            "session_id": session_id,
            "src_ip": src_ip,
            "attacker_type": classification,
            "risk_score": threat_score,
            "timestamp": ts,
            "confidence": confidence,
            "interest": interest,
            "threat_score": threat_score,
            "latest_command": command
        })

    if command:
        payload = {
            "session_id": session_id,
            "src_ip": src_ip,
            "command": command,
            "response": response,
            "attacker_type": classification,
            "risk_score": threat_score,
            "timestamp": ts,
            "response_time": response_time,
            "confidence": confidence,
            "interest": interest,
            "threat_score": threat_score,
            "latest_command": command
        }
        socketio.emit("command_executed", payload)

        if threat_score > 80:
            socketio.emit("alert", {
                "session_id": session_id,
                "src_ip": src_ip,
                "message": f"HIGH RISK [{classification}] command from {src_ip}: {command[:80]}",
                "risk_score": threat_score,
                "timestamp": ts
            })

    if event_type == "session_end":
        sess_row = conn.execute(
            "SELECT start_time FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        session_duration = duration_seconds(sess_row["start_time"] if sess_row else ts, ts)
        conn.execute(
            "UPDATE sessions SET status='ended', end_time=?, session_duration=? WHERE session_id=?",
            (ts, session_duration, session_id)
        )
        conn.commit()
        socketio.emit("session_end", {
            "session_id": session_id,
            "timestamp": ts,
            "session_duration": session_duration
        })

    conn.close()
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
    print("  MIRAGE Live Monitor")
    print("  Dashboard : http://localhost:6001")
    print("  API       : http://localhost:6001/api/sessions")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=6001, debug=False, allow_unsafe_werkzeug=True)

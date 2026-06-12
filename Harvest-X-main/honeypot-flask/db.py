"""
db.py
=====
MongoDB connection and logging helpers.
All attack sessions are stored in the 'honeypot' database,
'attack_logs' collection.
"""

from datetime import datetime
import pymongo
import threading
import urllib.request
import json

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME   = "honeypot"
COL_NAME  = "attack_logs"

# ── Connect ────────────────────────────────────────────────────────────────
try:
    _client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
    _client.server_info()          # raises if not reachable
    _db  = _client[DB_NAME]
    _col = _db[COL_NAME]
    _col.create_index("ip")
    _col.create_index("timestamp")
    MONGO_AVAILABLE = True
    print("[DB] MongoDB connected.")
except Exception as e:
    MONGO_AVAILABLE = False
    _col = None
    print(f"[DB] MongoDB not available — logs stored in memory only. ({e})")

import os

FALLBACK_FILE = "honeypot_logs.json"
def _load_fallback():
    if os.path.exists(FALLBACK_FILE):
        try:
            with open(FALLBACK_FILE, "r") as f:
                logs = json.load(f)
                for log in logs:
                    if isinstance(log.get("timestamp"), str):
                        try:
                            log["timestamp"] = datetime.fromisoformat(log["timestamp"])
                        except Exception:
                            pass
                return logs
        except Exception:
            return []
    return []

def _save_fallback(logs):
    try:
        save_logs = []
        for d in logs:
            safe_d = dict(d)
            if isinstance(safe_d.get("timestamp"), datetime):
                safe_d["timestamp"] = safe_d["timestamp"].isoformat()
            save_logs.append(safe_d)
        with open(FALLBACK_FILE, "w") as f:
            json.dump(save_logs, f)
    except Exception as e:
        print(f"[DB Error] Could not save fallback: {e}")

# Persistent fallback log when MongoDB is unavailable
_memory_log = _load_fallback()


def log_attack(ip: str, path: str, method: str,
               headers: dict, body: str,
               attack_type: str, features: list, prediction: int, session_id: str = None,
               attacker_profile: dict = None, cmd_response: str = None):
    """
    Insert one attack record.
    Fields:
      ip           - attacker IP
      timestamp    - UTC datetime
      path         - request path
      method       - GET / POST
      headers      - dict of request headers
      body         - raw POST body (truncated to 2 KB)
      attack_type  - 'normal' | 'sql_injection' | 'xss' | 'traversal' | 'brute_force' | 'attack'
      features     - list of 6 ML feature values
      prediction   - 0 (normal) or 1 (attack)
    """
    doc = {
        "ip":          ip,
        "timestamp":   datetime.utcnow(),
        "path":        path,
        "method":      method,
        "headers":     dict(headers),
        "body":        body[:2048] if body else "",
        "attack_type": attack_type,
        "features":    features,
        "prediction":  prediction,
    }
    if MONGO_AVAILABLE:
        try:
            _col.insert_one(doc)
        except Exception:
            pass
    else:
        _memory_log.append(doc)
        _save_fallback(_memory_log)
        
    # Forward to MIRAGE HoneyWatch (port 8000) AND Live Monitor (port 6001)
    if prediction == 1:
        def _send():
            import time
            action = f"{method} {path}"
            if body:
                action += f" | {body[:60]}"
            sid = session_id if session_id else f"web_{ip.replace('.','_')}_{int(time.time())}"

            # ── Forward to MIRAGE (existing) ───────────────────────────
            try:
                url8 = "http://127.0.0.1:8000/api/web-event"
                p8 = {"session_id": sid, "src_ip": ip, "action": action,
                      "attack_type": attack_type.upper().replace('_', ' '), "confidence": 0.95}
                d8 = json.dumps(p8).encode('utf-8')
                req8 = urllib.request.Request(url8, data=d8, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req8, timeout=2)
            except Exception as e:
                print(f"[FORWARD ERROR] MIRAGE (8000): {e}")

            # ── Forward to Live Monitor (NEW) ──────────────────────────
            try:
                url6 = "http://127.0.0.1:6001/api/ingest"
                final_resp = cmd_response if cmd_response else f"[{attack_type}] Logged at {datetime.utcnow().strftime('%H:%M:%S')} UTC"
                
                # Check for classification in attacker profile
                p_class = "APT"
                p_risk = 95
                if attacker_profile:
                    p_class = attacker_profile.get("classification") or p_class
                    t_score = attacker_profile.get("threat_score")
                    if t_score is not None:
                        p_risk = t_score

                p6 = {
                    "session_id": sid,
                    "src_ip": ip,
                    "command": action,
                    "response": final_resp,
                    "attacker_type": p_class,
                    "risk_score": p_risk,
                    "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "command_executed",
                    "attacker_profile": attacker_profile
                }
                d6 = json.dumps(p6).encode('utf-8')
                req6 = urllib.request.Request(url6, data=d6, headers={'Content-Type': 'application/json'})
                urllib.request.urlopen(req6, timeout=2)
            except Exception as e:
                print(f"[FORWARD ERROR] Live Monitor (6001): {e}")

        threading.Thread(target=_send, daemon=True).start()



def get_recent_logs(limit: int = 50) -> list:
    """Return most recent attack logs."""
    if MONGO_AVAILABLE:
        try:
            docs = list(_col.find({}, {"_id": 0})
                           .sort("timestamp", pymongo.DESCENDING)
                           .limit(limit))
            # Convert datetime to string for JSON serialisation
            for d in docs:
                d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            return docs
        except Exception:
            pass
    # fallback
    logs = list(reversed(_memory_log[-limit:]))
    for d in logs:
        if isinstance(d.get("timestamp"), datetime):
            d["timestamp"] = d["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return logs


def get_stats() -> dict:
    """Aggregate stats for the dashboard."""
    if MONGO_AVAILABLE:
        try:
            total   = _col.count_documents({})
            attacks = _col.count_documents({"prediction": 1})
            by_type = list(_col.aggregate([
                {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}}
            ]))
            return {
                "total": total,
                "attacks": attacks,
                "normal": total - attacks,
                "by_type": {d["_id"]: d["count"] for d in by_type},
            }
        except Exception:
            pass
    total   = len(_memory_log)
    attacks = sum(1 for d in _memory_log if d.get("prediction") == 1)
    return {"total": total, "attacks": attacks, "normal": total - attacks, "by_type": {}}

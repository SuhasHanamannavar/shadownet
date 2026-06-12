"""
live_session.py
===============
Tracks active attacker sessions in real-time.
- Maintains per-session state (commands, timings, AI commentary)
- Pushes live events to the dashboard WebSocket
- Calls OpenAI to explain WHAT the attacker is trying to do
"""

import time
import threading
import config

# In-memory store of active sessions
# { session_id: { ip, commands: [{cmd, ts, ai_comment, risk}], classification, status } }
active_sessions = {}
_lock = threading.Lock()

# Broadcast callback (set by main.py)
_broadcast_fn = None

def set_broadcast(fn):
    global _broadcast_fn
    _broadcast_fn = fn

def _push(event: dict):
    if _broadcast_fn:
        _broadcast_fn(event)

def _ai_comment(cmd: str, session_context: list) -> str:
    """Ask OpenAI what this command means in context. Returns short explanation."""
    try:
        import openai
        client = openai.OpenAI(api_key=config.OPENAI_API_KEY)
        prev = [c['cmd'] for c in session_context[-4:]]
        prompt = (
            f"An attacker just ran this command in a honeypot: `{cmd}`\n"
            f"Previous commands: {prev}\n"
            "In ONE short sentence (max 12 words), explain what the attacker is TRYING to do. "
            "Be direct. No fluff."
        )
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=40,
            temperature=0.3
        )
        return resp.choices[0].message.content.strip()
    except Exception:
        return _heuristic_comment(cmd)

def _heuristic_comment(cmd: str) -> str:
    """Offline fallback: rule-based command description."""
    c = cmd.lower().strip()
    if c.startswith("whoami") or c.startswith("id"): return "Checking current user identity."
    if "passwd" in c or "/etc/shadow" in c: return "Harvesting password hashes."
    if "ifconfig" in c or "ip addr" in c or "netstat" in c: return "Mapping network interfaces."
    if "find" in c and "pem" in c: return "Hunting for private SSL/SSH keys."
    if "find" in c and "conf" in c: return "Searching for configuration files."
    if "grep" in c and "pass" in c: return "Searching for hardcoded passwords."
    if "wget" in c or "curl" in c: return "Downloading malicious payload."
    if "chmod" in c: return "Changing file permissions to execute payload."
    if "crontab" in c: return "Installing persistence via cron job."
    if "rm -rf" in c: return "Attempting to destroy the filesystem."
    if "bash -i" in c or "nc -e" in c: return "Opening reverse shell to attacker C2."
    if "ssh" in c: return "Attempting lateral movement via SSH."
    if "nmap" in c: return "Scanning internal network for hosts."
    if "sudo" in c or "su " in c: return "Attempting privilege escalation."
    if "uname" in c or "lsb_release" in c: return "Gathering OS fingerprint."
    if "history" in c: return "Reading bash command history."
    if "cat /etc/hosts" in c: return "Reading internal hostname mappings."
    if ".env" in c or "aws_" in c.lower(): return "Hunting for API keys and secrets."
    return "Executing command in honeypot environment."

def _risk_score(cmd: str) -> int:
    """0-100 risk score for a single command."""
    c = cmd.lower()
    if any(k in c for k in ["rm -rf", "dd if=", "mkfs", "shred", "> /dev/sd"]): return 95
    if any(k in c for k in ["bash -i", "nc -e", "/dev/tcp", "python3 -c 'import socket"]): return 90
    if any(k in c for k in ["wget", "curl", "chmod +x", "nohup"]): return 75
    if any(k in c for k in ["crontab", "authorized_keys", "adduser", "useradd"]): return 80
    if any(k in c for k in ["shadow", "passwd", ".env", "id_rsa", "aws_"]): return 70
    if any(k in c for k in ["nmap", "masscan", "hydra", "ssh "]): return 65
    if any(k in c for k in ["sudo", "su -", "find /", "grep -r"]): return 45
    if any(k in c for k in ["whoami", "id", "uname", "ifconfig", "netstat", "ps"]): return 25
    if any(k in c for k in ["ls", "pwd", "cat", "echo", "env"]): return 10
    return 20

def session_started(session_id: str, src_ip: str):
    with _lock:
        active_sessions[session_id] = {
            "session_id": session_id,
            "src_ip":     src_ip,
            "start_ts":   time.time(),
            "commands":   [],
            "classification": "Unknown",
            "confidence": 0.0,
            "status":     "active",
            "fake_os":    "Ubuntu 22.04 LTS",
        }
    _push({
        "event":      "session_started",
        "session_id": session_id,
        "src_ip":     src_ip,
        "ts":         time.time(),
    })

def command_executed(session_id: str, src_ip: str, cmd: str):
    # Check outside the lock first, or just use a boolean
    needs_start = False
    with _lock:
        if session_id not in active_sessions:
            needs_start = True
            
    if needs_start:
        session_started(session_id, src_ip)

    # Run AI comment in background so we don't block the log watcher
    def _process():
        context = active_sessions[session_id]["commands"]
        comment = _ai_comment(cmd, context)
        risk    = _risk_score(cmd)

        entry = {
            "cmd":        cmd,
            "ts":         time.time(),
            "ai_comment": comment,
            "risk":       risk,
        }
        with _lock:
            active_sessions[session_id]["commands"].append(entry)

        _push({
            "event":      "command",
            "session_id": session_id,
            "src_ip":     src_ip,
            "cmd":        cmd,
            "ai_comment": comment,
            "risk":       risk,
            "ts":         time.time(),
        })

    threading.Thread(target=_process, daemon=True).start()

def session_classified(session_id: str, classification: dict):
    with _lock:
        if session_id in active_sessions:
            active_sessions[session_id]["classification"] = classification.get("type", "Unknown")
            active_sessions[session_id]["confidence"]     = classification.get("confidence", 0)

    _push({
        "event":          "classified",
        "session_id":     session_id,
        "classification": classification,
        "ts":             time.time(),
    })

def session_ended(session_id: str):
    with _lock:
        if session_id in active_sessions:
            active_sessions[session_id]["status"] = "closed"
    _push({
        "event":      "session_ended",
        "session_id": session_id,
        "ts":         time.time(),
    })

def get_all_sessions() -> dict:
    with _lock:
        return dict(active_sessions)

def get_session(session_id: str) -> dict:
    with _lock:
        return active_sessions.get(session_id)

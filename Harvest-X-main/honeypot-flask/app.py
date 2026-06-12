"""
app.py  (WebSocket upgrade)
===========================
Drop-in replacement for your existing honeypot-flask/app.py.

Changes vs original:
  • flask-socketio added — install with:  pip install flask-socketio
  • emit_attack() called inside log_attack() hook so every new attack
    is pushed to the dashboard the instant it's detected (no polling).
  • /honeypot-dashboard/api/logs and /api/stats kept for backwards compat.
  • Everything else is identical to your original file.

Run:
    python app.py
"""

import os
import re
import time
import json
import random
import string
import logging
from datetime import datetime
from functools import wraps

import joblib
import numpy as np
from flask import (Flask, request, render_template, session,
                   redirect, url_for, jsonify, make_response)
from flask_socketio import SocketIO, emit          # NEW

import db
import real_db
from telegram_alert import maybe_alert

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.urandom(24)

# async_mode='threading' works without eventlet/gevent installed
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")   # NEW

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname)s %(message)s')
log = logging.getLogger(__name__)

# ── Load ML model ──────────────────────────────────────────────────────────
MODEL_PATH = "model.pkl"
try:
    model = joblib.load(MODEL_PATH)
    log.info(f"[Model] Loaded from {MODEL_PATH}")
except FileNotFoundError:
    model = None
    log.warning("[Model] model.pkl not found — run model_trainer.py first. Falling back to rule-based detection.")

# ── Request frequency tracker ──────────────────────────────────────────────
_request_times: dict[str, list] = {}
BRUTE_WINDOW  = 60
BRUTE_LIMIT   = 15

_failed_logins: dict[str, int] = {}
FAILED_LOGIN_LIMIT = 3

# ── Regex patterns ─────────────────────────────────────────────────────────
SQL_RE   = re.compile(
    r"(select|insert|update|delete|drop|union|exec|--|%27|'|;|1=1|or\s+1|benchmark|sleep\s*\()",
    re.IGNORECASE)
XSS_RE   = re.compile(
    r"(<script|javascript:|onerror=|alert\s*\(|onload=|<img|<svg|eval\(|document\.cookie)",
    re.IGNORECASE)
TRAV_RE  = re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|/windows/system32)",
                      re.IGNORECASE)


# ══════════════════════════════════════════════════════════════════════════
# NEW — WebSocket helpers
# ══════════════════════════════════════════════════════════════════════════

def emit_attack(attack_record: dict):
    """
    Push a new attack event to ALL connected dashboard clients instantly.
    Called right after db.log_attack() so the dashboard updates in real time.
    """
    # Make the record JSON-serialisable (datetime → string)
    safe = dict(attack_record)
    if isinstance(safe.get("timestamp"), datetime):
        safe["timestamp"] = safe["timestamp"].isoformat()

    socketio.emit("new_attack", safe, namespace="/dashboard")
    log.info(f"[WS] Pushed new_attack event to dashboard clients")


@socketio.on("connect", namespace="/dashboard")
def on_dashboard_connect():
    log.info("[WS] Dashboard client connected")
    # Send the last 50 logs immediately on connect so the page isn't blank
    recent = db.get_recent_logs(50)
    emit("init_logs", recent)


@socketio.on("disconnect", namespace="/dashboard")
def on_dashboard_disconnect():
    log.info("[WS] Dashboard client disconnected")


# ══════════════════════════════════════════════════════════════════════════
# Feature Extraction  (unchanged)
# ══════════════════════════════════════════════════════════════════════════

def extract_features(req) -> tuple[list, str]:
    path    = req.path or ""
    args    = req.query_string.decode("utf-8", errors="ignore")
    body    = req.get_data(as_text=True) or ""
    payload = args + " " + body

    f1_path_len    = len(path)
    f2_payload_len = len(payload)
    f3_sql         = 1 if SQL_RE.search(payload) or SQL_RE.search(path) else 0
    f4_xss         = 1 if XSS_RE.search(payload) or XSS_RE.search(path) else 0
    f5_traversal   = 1 if TRAV_RE.search(path) or TRAV_RE.search(payload) else 0
    f6_params      = len(req.args) + len(req.form)

    features = [f1_path_len, f2_payload_len, f3_sql, f4_xss, f5_traversal, f6_params]

    if f3_sql:          attack_type = "sql_injection"
    elif f4_xss:        attack_type = "xss"
    elif f5_traversal:  attack_type = "path_traversal"
    else:               attack_type = "attack"

    return features, attack_type


def is_brute_force(ip: str) -> bool:
    now = time.time()
    times = _request_times.setdefault(ip, [])
    times.append(now)
    _request_times[ip] = [t for t in times if now - t < BRUTE_WINDOW]
    return len(_request_times[ip]) > BRUTE_LIMIT


# ══════════════════════════════════════════════════════════════════════════
# Patched log_attack wrapper — emits WS event after every DB write
# ══════════════════════════════════════════════════════════════════════════

def log_and_emit(**kwargs):
    """
    Wrapper around db.log_attack() that also fires a WebSocket event so
    the dashboard updates in real time without polling.
    """
    db.log_attack(**kwargs)
    maybe_alert(
        attack_type=kwargs.get("attack_type", "attack"),
        ip=kwargs.get("ip", "unknown"),
        path=kwargs.get("path", "/"),
        confidence=1.0,
        session_id=kwargs.get("session_id"),
    )
    record = {
        "ip":          kwargs.get("ip"),
        "path":        kwargs.get("path"),
        "method":      kwargs.get("method"),
        "attack_type": kwargs.get("attack_type"),
        "features":    kwargs.get("features"),
        "prediction":  kwargs.get("prediction"),
        "session_id":  kwargs.get("session_id"),
        "timestamp":   datetime.utcnow().isoformat(),
        "response":    kwargs.get("cmd_response"),
        "attacker_profile": kwargs.get("attacker_profile")
    }
    emit_attack(record)



# ══════════════════════════════════════════════════════════════════════════
# Gateway Middleware  (unchanged logic, uses log_and_emit)
# ══════════════════════════════════════════════════════════════════════════

def classify_request() -> bool:
    if request.path.startswith('/static') or request.path.startswith('/honeypot-dashboard'):
        return False

    ip = request.remote_addr

    if is_brute_force(ip):
        session['is_attacker'] = True
        return True

    if session.get('is_attacker'):
        return True

    features, attack_type = extract_features(request)

    if model:
        pred = int(model.predict(np.array(features).reshape(1, -1))[0])
    else:
        pred = 1 if any([features[2], features[3], features[4]]) else 0

    if pred == 1:
        session['is_attacker'] = True
        _, attack_type = extract_features(request)
        body = request.get_data(as_text=True)
        log_and_emit(                          # ← was db.log_attack
            ip=ip,
            path=request.path,
            method=request.method,
            headers=dict(request.headers),
            body=body,
            attack_type=attack_type,
            features=features,
            prediction=pred,
        )
        log.warning(f"[ATTACK] {ip} — {attack_type} — {request.method} {request.path}")
        return True

    return False


# ══════════════════════════════════════════════════════════════════════════
# ROUTES  (identical to original except db.log_attack → log_and_emit)
# ══════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    if classify_request():
        return render_template("fake_index.html")
    return render_template("real_index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    is_attack = classify_request()
    ip = request.remote_addr

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        sql_patterns = [r"' OR 1=1", r"UNION SELECT", r"--", r"/\*", r"; DROP"]
        if any(re.search(p, username, re.IGNORECASE) for p in sql_patterns) or \
           any(re.search(p, password, re.IGNORECASE) for p in sql_patterns):
            is_attack = True
            session['is_attacker'] = True

        if is_attack:
            time.sleep(random.uniform(0.5, 1.5))
            import time as tmod
            mirage_sid = f"web_{ip.replace('.','_')}_{int(tmod.time())}"
            session['mirage_sid'] = mirage_sid
            session['attacker_profile'] = {
                "classification": "Scanner",
                "interest": "Reconnaissance",
                "command_history": [],
                "session_duration": 0,
                "threat_score": 10,
                "confidence": 50
            }
            session['session_start_time'] = tmod.time()
            log_and_emit(                      # ← was db.log_attack
                ip=ip, path=request.path, method=request.method,
                headers=dict(request.headers),
                body=f"username={username}&password={password}",
                attack_type="credential_harvest",
                features=extract_features(request)[0], prediction=1,
                session_id=mirage_sid,
                attacker_profile=session['attacker_profile']
            )
            session['fake_user'] = username
            _failed_logins[ip] = 0
            return redirect(url_for("admin"))

        user_record = real_db.verify_user(username, password)
        if user_record:
            _failed_logins[ip] = 0
            session['user'] = user_record['username']
            session['role'] = user_record['role']
            return redirect(url_for("real_dashboard"))

        _failed_logins[ip] = _failed_logins.get(ip, 0) + 1
        attempts = _failed_logins[ip]
        log.warning(f"[LOGIN] Failed attempt {attempts}/{FAILED_LOGIN_LIMIT} from {ip} — user='{username}'")

        if attempts >= FAILED_LOGIN_LIMIT:
            session['is_attacker'] = True
            session['fake_user'] = username
            import time as tmod
            mirage_sid = f"web_{ip.replace('.','_')}_{int(tmod.time())}"
            session['mirage_sid'] = mirage_sid
            session['attacker_profile'] = {
                "classification": "Scanner",
                "interest": "Reconnaissance",
                "command_history": [],
                "session_duration": 0,
                "threat_score": 10,
                "confidence": 50
            }
            session['session_start_time'] = tmod.time()
            log_and_emit(                      # ← was db.log_attack
                ip=ip, path=request.path, method=request.method,
                headers=dict(request.headers),
                body=f"username={username}&password={password}",
                attack_type="brute_force",
                features=extract_features(request)[0], prediction=1,
                session_id=mirage_sid,
                attacker_profile=session['attacker_profile']
            )
            log.warning(f"[HONEYPOT] {ip} exceeded {FAILED_LOGIN_LIMIT} failed logins — redirecting to fake panel")
            time.sleep(random.uniform(0.8, 1.5))
            return redirect(url_for("admin"))

        remaining = FAILED_LOGIN_LIMIT - attempts
        error = f"Invalid credentials. {remaining} attempt{'s' if remaining > 1 else ''} remaining."
        return render_template("real_login.html", error=error, attempts=attempts)

    if is_attack:
        return render_template("fake_login.html")
    return render_template("real_login.html")


@app.route("/dashboard")
def real_dashboard():
    if session.get('is_attacker'):
        return redirect(url_for("admin"))
    if not session.get('user'):
        return redirect(url_for("login"))
    user_info = real_db.get_user_by_username(session['user'])
    role = user_info['role'] if user_info else 'Unknown'
    return render_template("real_dashboard.html", user=session['user'], role=role)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    classify_request()
    if request.method == "POST":
        action = request.form.get("action", "")
        mirage_sid = session.get('mirage_sid')
        log_and_emit(                          # ← was db.log_attack
            ip=request.remote_addr,
            path="/admin",
            method="POST",
            headers=dict(request.headers),
            body=request.get_data(as_text=True),
            attack_type="admin_panel_interaction",
            features=extract_features(request)[0],
            prediction=1,
            session_id=mirage_sid
        )
        time.sleep(random.uniform(0.3, 1.0))

        msg = f"Action '{action}' executed."
        if action == "open_users_module":
            msg = "Error 403: Module 'Users' is currently locked for maintenance by root."
        elif action == "download_system_logs":
            msg = "Generating logs... Error: Insufficient storage quota in /var/log/."
        elif action == "view_network_map":
            msg = "Permission Denied: Your current role cannot view topology maps."
        elif action == "open_settings":
            msg = "Settings module is offline. Please contact IT support."
        elif action.startswith("reset_pw_"):
            msg = "Password reset link generated and sent to the user's primary email address."
        elif action == "export_users":
            msg = "Export initiated. The CSV file will be emailed to you shortly."

        status_val = "error" if ("Error" in msg or "Denied" in msg) else "success"
        return jsonify({"status": status_val, "message": msg})
    return render_template("fake_admin.html",
                           fake_user=session.get('fake_user', 'admin'),
                           server_ip="192.168.1." + str(random.randint(10, 50)),
                           mirage_sid=session.get('mirage_sid', ''))


@app.route("/honeypot-command", methods=["POST"])
def honeypot_command():
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd", "")
    cwd = data.get("cwd", "~")
    ip = request.remote_addr
    
    # Initialize attacker profile in session if it doesn't exist
    if 'attacker_profile' not in session:
        session['attacker_profile'] = {
            "classification": "Scanner",
            "interest": "Reconnaissance",
            "command_history": [],
            "session_duration": 0,
            "threat_score": 10,
            "confidence": 50
        }
        session['session_start_time'] = time.time()
        
    profile = session['attacker_profile']
    profile["command_history"].append(cmd)
    
    # Calculate duration
    start_time = session.get('session_start_time', time.time())
    profile["session_duration"] = int(time.time() - start_time)
    
    # Track suspect command patterns to calculate interest and threat score
    cmd_lower = cmd.lower().strip()
    
    if any(db_kw in cmd_lower for db_kw in ["mysql", "mongo", "sqlite"]):
        profile["interest"] = "Database"
        profile["threat_score"] = min(profile["threat_score"] + 15, 100)
    elif any(cred_kw in cmd_lower for cred_kw in ["passwd", "shadow", "password"]):
        profile["interest"] = "Credentials"
        profile["threat_score"] = min(profile["threat_score"] + 20, 100)
    elif any(mal_kw in cmd_lower for mal_kw in ["wget", "curl"]):
        profile["interest"] = "Malware"
        profile["threat_score"] = min(profile["threat_score"] + 40, 100)
        profile["classification"] = "Bot"
        profile["confidence"] = 100
    elif any(rec_kw in cmd_lower for rec_kw in ["ls", "find", "whoami", "pwd", "cd"]):
        if profile["interest"] not in ["Database", "Credentials", "Malware"]:
            profile["interest"] = "Reconnaissance"
        profile["threat_score"] = min(profile["threat_score"] + 2, 100)
        
    session['attacker_profile'] = profile
    
    # Process the command output based on the Adaptive Fake Filesystem rules
    response_out = ""
    style_class = "resp"
    new_cwd = cwd
    
    # 1. ls command
    if cmd_lower == "ls" or cmd_lower.startswith("ls "):
        if "-l" in cmd_lower:
            response_out = (
                "total 20\n"
                "drwxr-xr-x  2 admin admin  4096 May  3 12:05 Documents\n"
                "drwxr-xr-x  2 admin admin  4096 May  3 12:05 Downloads\n"
                "drwxr-xr-x  2 admin admin  4096 May  3 12:05 configs\n"
                "-rw-r--r--  1 admin admin 12482 May  3 12:05 mysql_backup.sql\n"
                "-rw-r--r--  1 admin admin   254 May  3 12:05 passwords.txt"
            )
        else:
            response_out = "Documents  Downloads  configs  mysql_backup.sql  passwords.txt"
            
    # 2. Database command
    elif any(db_kw in cmd_lower for db_kw in ["mysql", "mongo", "sqlite"]):
        response_out = (
            "Exposed database topologies found:\n"
            "  - customer_db  [sqlite3]\n"
            "  - admin_db     [mongodb]\n"
            "  - employee_db  [mysql]\n"
            "Connecting as default admin... Success. Type 'help' for database query formats."
        )
        style_class = "info"
        
    # 3. Read passwords
    elif cmd_lower.startswith("cat passwords.txt") or cmd_lower == "cat passwords.txt":
        response_out = (
            "admin : admin123\n"
            "root : Password@2025\n"
            "dbadmin : welcome123"
        )
        style_class = "warn"
        
    # 4. Searches
    elif cmd_lower.startswith("find ") or cmd_lower.startswith("locate "):
        response_out = (
            "/etc/passwd\n"
            "/home/admin\n"
            "/var/log\n"
            "/secrets"
        )
        style_class = "warn"
        
    # 5. Downloads malware
    elif cmd_lower.startswith("wget ") or cmd_lower.startswith("curl "):
        response_out = (
            "Downloading payload from source... 100%\n"
            "Saved payload to /tmp/malware_agent\n"
            "Applying permissions: chmod +x /tmp/malware_agent\n"
            "Executing malicious payload... OK"
        )
        style_class = "err"
        
    # 6. cd command
    elif cmd_lower.startswith("cd "):
        target = cmd[3:].strip()
        if target == "~" or target == "/home/admin":
            new_cwd = "~"
            response_out = ""
        elif target == "/":
            new_cwd = "/"
            response_out = ""
        elif target in ["Documents", "Downloads", "configs"]:
            new_cwd = target
            response_out = ""
        else:
            response_out = f"-bash: cd: {target}: No such file or directory"
            style_class = "err"
            
    # 7. Common unix utilities emulators
    elif cmd_lower == "whoami":
        response_out = "admin"
    elif cmd_lower == "id":
        response_out = "uid=0(admin) gid=0(root) groups=0(root),27(sudo)"
    elif cmd_lower == "pwd":
        response_out = "/home/admin" if new_cwd == "~" else f"/{new_cwd}"
    elif cmd_lower == "uname -a":
        response_out = "Linux corpnet-prod-01 5.4.0-150-generic #167-Ubuntu SMP x86_64 GNU/Linux"
    elif cmd_lower == "uname":
        response_out = "Linux"
    elif cmd_lower == "hostname":
        response_out = "corpnet-prod-01"
    elif cmd_lower == "clear":
        response_out = "__CLEAR__"
    elif cmd_lower == "help":
        response_out = "Available commands: ls, cat, whoami, id, hostname, uname, pwd, cd, mysql, mongo, sqlite, find, locate, clear, help"
        style_class = "info"
    else:
        response_out = f"-bash: {cmd.split(' ')[0]}: command not found"
        style_class = "err"
        
    mirage_sid = session.get('mirage_sid')
    log.warning(f"[CONSOLE] {ip} executed: {cmd} -> Response: {response_out}")
    
    log_and_emit(
        ip=ip, path="/admin/console", method="POST",
        headers=dict(request.headers),
        body=f"cmd={cmd}",
        attack_type="terminal_command",
        features=extract_features(request)[0], prediction=1,
        session_id=mirage_sid,
        attacker_profile=profile,
        cmd_response=response_out
    )
    
    return jsonify({
        "status": "ok",
        "response": response_out,
        "style_class": style_class,
        "cwd": new_cwd
    })


@app.route("/admin/database", methods=["GET", "POST"])
def fake_database():
    classify_request()
    if request.method == "POST":
        query = request.form.get("query", "")
        log_and_emit(                          # ← was db.log_attack
            ip=request.remote_addr, path="/admin/database", method="POST",
            headers=dict(request.headers), body=f"query={query}",
            attack_type="fake_db_query", features=extract_features(request)[0], prediction=1,
            session_id=session.get('mirage_sid')
        )
        time.sleep(random.uniform(0.2, 0.8))
        fake_rows = [
            {"id": i, "username": f"user_{i:03d}",
             "email": f"user{i}@corp.internal",
             "password": "".join(random.choices(string.hexdigits, k=32))}
            for i in range(1, random.randint(4, 12))
        ]
        return jsonify({"rows": fake_rows, "affected": len(fake_rows), "time": "0.003s"})
    return render_template("fake_db.html")


@app.route("/api/users", methods=["GET", "POST"])
@app.route("/api/admin", methods=["GET", "POST"])
@app.route("/wp-admin", methods=["GET", "POST"])
@app.route("/phpmyadmin", methods=["GET", "POST"])
@app.route("/.env", methods=["GET"])
@app.route("/config.php", methods=["GET"])
def honeypot_trap():
    ip = request.remote_addr
    session['is_attacker'] = True
    mirage_sid = session.get('mirage_sid')
    if not mirage_sid:
        import time as tmod
        mirage_sid = f"web_{ip.replace('.','_')}_{int(tmod.time())}"
        session['mirage_sid'] = mirage_sid

    features, atype = extract_features(request)
    log_and_emit(ip=ip, path=request.path, method=request.method,   # ← was db.log_attack
                 headers=dict(request.headers), body=request.get_data(as_text=True),
                 attack_type=f"scanner_{atype}", features=features, prediction=1, session_id=mirage_sid)
    log.warning(f"[TRAP] {ip} hit scanner trap: {request.path}")
    if ".env" in request.path:
        return make_response(
            "APP_KEY=base64:fakekey1234\nDB_PASSWORD=P@ssw0rd!\nAWS_SECRET=FAKE_SECRET",
            200, {"Content-Type": "text/plain"}
        )
    return render_template("fake_admin.html", fake_user="admin", server_ip="10.0.0.1")


# ── Monitoring Dashboard (REST endpoints kept for backwards compat) ────────
@app.route("/honeypot-dashboard")
def honeypot_dashboard():
    return render_template("dashboard.html")

@app.route("/honeypot-dashboard/api/logs")
def api_logs():
    return jsonify(db.get_recent_logs(50))

@app.route("/honeypot-dashboard/api/stats")
def api_stats():
    return jsonify(db.get_stats())


@app.route("/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def catch_all(subpath):
    is_attack = classify_request()
    if is_attack:
        mirage_sid = session.get('mirage_sid')
        if not mirage_sid:
            import time as tmod
            mirage_sid = f"web_{request.remote_addr.replace('.','_')}_{int(tmod.time())}"
            session['mirage_sid'] = mirage_sid

        log_and_emit(ip=request.remote_addr, path=f"/{subpath}",   # ← was db.log_attack
                     method=request.method, headers=dict(request.headers),
                     body=request.get_data(as_text=True),
                     attack_type="unknown_path", features=extract_features(request)[0], prediction=1,
                     session_id=mirage_sid)
        return render_template("fake_admin.html",
                               fake_user=session.get('fake_user', 'admin'),
                               server_ip="10.0.0." + str(random.randint(1, 50)),
                               mirage_sid=mirage_sid)
    return render_template("real_index.html")


# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    real_db.init_db()
    log.info("Starting MIRAGE Honeypot with WebSocket support on http://localhost:5000")
    # Use socketio.run() instead of app.run() to activate WebSocket support
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)

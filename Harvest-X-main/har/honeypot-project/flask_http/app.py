import os
import json
import sqlite3
import hashlib
from datetime import datetime
from flask import Flask, request, render_template_string, render_template, jsonify, redirect

from parser import get_recent_logs
from classifier import classify_events
from response_engine import generate_response

app = Flask(__name__)
LOG_FILE = "/app/logs/http_logs.json"
DB_FILE = "/app/logs/honeypot.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS http_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT,
            path TEXT,
            method TEXT,
            data TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_request(req):
    ip = req.remote_addr
    timestamp = datetime.utcnow().isoformat() + "Z"
    path = req.path
    method = req.method
    
    if req.form:
        data = json.dumps(req.form.to_dict())
    else:
        data = req.get_data(as_text=True)
        
    log_entry = {
        "service": "flask_http",
        "ip": ip,
        "timestamp": timestamp,
        "path": path,
        "method": method,
        "data": data
    }

    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Error writing to JSON log: {e}")

    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute(
            "INSERT INTO http_logs (ip, timestamp, path, method, data) VALUES (?, ?, ?, ?, ?)",
            (ip, timestamp, path, method, data)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error writing to SQLite: {e}")

# Dashboard routes
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/stats')
def api_stats():
    events = get_recent_logs(300)
    sessions = classify_events(events)
    return jsonify({
        "events": events[:50],
        "sessions": sessions
    })

# Terminal endpoints
@app.route('/admin/terminal')
def terminal():
    return render_template('terminal.html')

@app.route('/api/terminal/run', methods=['POST'])
def terminal_run():
    data = request.json or {}
    cmd = data.get('command', '')
    
    log_entry = {
        "service": "HTTP_Terminal",
        "ip": request.remote_addr,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "path": "/api/terminal/run",
        "method": "POST",
        "data": json.dumps({"command": cmd})
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except:
        pass

    response = generate_response(cmd)
    
    # Optional Blockchain hashing simulation
    log_hash = hashlib.sha256(f"{request.remote_addr}{cmd}{datetime.utcnow().timestamp()}".encode()).hexdigest()
    
    return jsonify({"output": response, "tx_hash": log_hash})

# Honeytrap routes
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'])
def catch_all(path):
    if path.startswith('dashboard') or path.startswith('api/') or path.startswith('admin/terminal'):
        return "Not Found", 404
        
    log_request(request)
    
    if path == 'login':
        if request.method == 'POST':
            # Fake success trap!
            return redirect('/admin/terminal')
            
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Enterprise Security Portal</title>
                <style>
                    body { font-family: Arial, sans-serif; background-color: #f4f4f4; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
                    .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); width: 300px; text-align: center; }
                    input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
                    input[type="submit"] { background: #0056b3; color: white; border: none; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="login-box">
                    <h2>Admin Portal</h2>
                    <form method="POST" action="/login">
                        <input type="text" name="username" placeholder="Username" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <input type="submit" value="Login">
                    </form>
                </div>
            </body>
            </html>
        '''), 401
        
    if path == '':
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
            <title>Welcome to nginx!</title>
            <style>
                body {
                    width: 35em;
                    margin: 0 auto;
                    font-family: Tahoma, Verdana, Arial, sans-serif;
                }
            </style>
            </head>
            <body>
            <h1>Welcome to nginx!</h1>
            <p>If you see this page, the nginx web server is successfully installed and
            working. Further configuration is required.</p>
            <p>For online documentation and support please refer to
            <a href="http://nginx.org/">nginx.org</a>.<br/>
            Commercial support is available at
            <a href="http://nginx.com/">nginx.com</a>.</p>
            <p><em>Thank you for using nginx.</em></p>
            <!-- internal portal: /login -->
            </body>
            </html>
        '''), 200
    
    return "Not Found", 404

if __name__ == '__main__':
    os.makedirs("/app/logs", exist_ok=True)
    os.makedirs("/app/templates", exist_ok=True)
    init_db()
    app.run(host='0.0.0.0', port=8080)

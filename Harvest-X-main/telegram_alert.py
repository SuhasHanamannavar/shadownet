"""
telegram_alert.py
=================
Drop this file into your honeypot-flask/ folder.

Setup (one-time, ~3 minutes):
  1. Message @BotFather on Telegram → /newbot → copy the API token
  2. Message @userinfobot on Telegram → copy your Chat ID
  3. Set environment variables (or edit the defaults below):
       export TELEGRAM_TOKEN="123456:ABC-your-token-here"
       export TELEGRAM_CHAT_ID="987654321"
  4. pip install requests   (already likely installed)

Usage — call from app.py whenever an attack is detected:
  from telegram_alert import maybe_alert

  # Inside log_and_emit() or classify_request(), after db.log_attack():
  maybe_alert(attack_type, ip, path, confidence=0.95)

Behaviour:
  • Only fires when confidence >= ALERT_THRESHOLD (default 0.9 = 90%)
  • Rate-limited: max 1 alert per IP per COOLDOWN_SECONDS (default 300)
  • Runs in a background thread so it never slows down your Flask request
  • Silently logs errors — a Telegram outage will never crash your honeypot
"""

import os
import logging
import threading
import time
from datetime import datetime

import requests

log = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────
# Set these as environment variables, or replace the defaults below.
TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN",   "YOUR_BOT_TOKEN_HERE")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID_HERE")

# Only alert when model confidence is at or above this threshold (0.0–1.0)
ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "0.9"))

# Minimum seconds between alerts for the same IP (prevents spam)
COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN", "300"))

# Attack types that always trigger an alert regardless of cooldown
HIGH_PRIORITY_TYPES = {"sql_injection", "credential_harvest", "brute_force", "terminal_command"}

# Telegram API URL
_API_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"

# ── Internal cooldown tracker ──────────────────────────────────────────────
_last_alert: dict[str, float] = {}   # ip -> epoch timestamp of last alert
_lock = threading.Lock()


def _is_on_cooldown(ip: str, attack_type: str) -> bool:
    """Return True if this IP was recently alerted AND attack isn't high priority."""
    if attack_type in HIGH_PRIORITY_TYPES:
        return False   # always alert for critical attack types
    with _lock:
        last = _last_alert.get(ip, 0)
        return (time.time() - last) < COOLDOWN_SECONDS


def _record_alert(ip: str):
    with _lock:
        _last_alert[ip] = time.time()


def _format_message(attack_type: str, ip: str, path: str, confidence: float,
                    session_id: str = None, extra: dict = None) -> str:
    """Build a nicely formatted Telegram message."""
    emoji_map = {
        "sql_injection":        "💉",
        "xss":                  "🔴",
        "brute_force":          "🔨",
        "credential_harvest":   "🎣",
        "terminal_command":     "💻",
        "path_traversal":       "📂",
        "admin_panel_interaction": "🚪",
        "scanner_attack":       "🔍",
    }
    emoji = emoji_map.get(attack_type, "⚠️")
    conf_pct = f"{confidence * 100:.0f}%" if confidence else "rule-based"
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        f"{emoji} *MIRAGE HONEYPOT ALERT*",
        f"",
        f"*Attack type:* `{attack_type.replace('_', ' ').upper()}`",
        f"*Attacker IP:* `{ip}`",
        f"*Path hit:* `{path}`",
        f"*Confidence:* {conf_pct}",
        f"*Time:* {ts}",
    ]

    if session_id:
        lines.append(f"*Session ID:* `{session_id}`")

    if extra:
        for k, v in extra.items():
            lines.append(f"*{k}:* `{v}`")

    lines += ["", "📍 Check your dashboard for full session details."]
    return "\n".join(lines)


def _send(message: str):
    """POST the message to Telegram. Called in a background thread."""
    if TELEGRAM_TOKEN == "YOUR_BOT_TOKEN_HERE":
        log.warning("[Telegram] Token not configured — skipping alert. Set TELEGRAM_TOKEN env var.")
        return
    try:
        resp = requests.post(
            _API_URL,
            json={
                "chat_id":    TELEGRAM_CHAT_ID,
                "text":       message,
                "parse_mode": "Markdown",
            },
            timeout=10,
        )
        if resp.status_code == 200:
            log.info("[Telegram] Alert sent successfully.")
        else:
            log.warning(f"[Telegram] Unexpected response: {resp.status_code} — {resp.text[:200]}")
    except requests.exceptions.RequestException as e:
        log.error(f"[Telegram] Failed to send alert: {e}")


def maybe_alert(attack_type: str, ip: str, path: str,
                confidence: float = 1.0,
                session_id: str = None,
                extra: dict = None):
    """
    Public API — call this after every attack detection.

    Parameters:
        attack_type  : string from db.log_attack (e.g. 'sql_injection')
        ip           : attacker IP address
        path         : request path that triggered detection
        confidence   : ML model probability (0.0–1.0); use 1.0 for rule-based hits
        session_id   : optional MIRAGE session ID
        extra        : optional dict of additional fields to show in the alert
    """
    if confidence < ALERT_THRESHOLD:
        return   # below confidence threshold — no alert

    if _is_on_cooldown(ip, attack_type):
        log.debug(f"[Telegram] Skipping alert for {ip} — on cooldown")
        return

    _record_alert(ip)
    message = _format_message(attack_type, ip, path, confidence, session_id, extra)

    # Fire-and-forget in background thread so Flask request isn't blocked
    t = threading.Thread(target=_send, args=(message,), daemon=True)
    t.start()


# ── Quick integration snippet for app.py ──────────────────────────────────
# Add this import at the top of app.py:
#   from telegram_alert import maybe_alert
#
# Then inside log_and_emit(), after db.log_attack(**kwargs), add:
#
#   maybe_alert(
#       attack_type = kwargs.get("attack_type", "attack"),
#       ip          = kwargs.get("ip", "unknown"),
#       path        = kwargs.get("path", "/"),
#       confidence  = 1.0,   # or pass model.predict_proba()[0][1] for real confidence
#       session_id  = kwargs.get("session_id"),
#   )
#
# That's it — every high-confidence attack now sends a Telegram message.


# ── Standalone test ────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Sending test alert to Telegram...")
    maybe_alert(
        attack_type="sql_injection",
        ip="192.168.1.100",
        path="/login",
        confidence=0.97,
        session_id="web_192_168_1_100_1234567890",
        extra={"Simulated": "Yes — this is a test"},
    )
    time.sleep(3)   # wait for background thread
    print("Done — check your Telegram!")

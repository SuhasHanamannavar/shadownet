import os
from pathlib import Path

# Load .env from the project root (where this config.py lives)
env_path = Path(__file__).parent / ".env"
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=env_path, override=True)
except ImportError:
    pass

# ── Server ──
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8000))

# ── Groq AI ──
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_BASE_URL = os.environ.get("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

# ── Honeypot Ports ──
PORTS = {
    "ssh": int(os.environ.get("SSH_PORT", 2222)),
    "http": int(os.environ.get("HTTP_PORT", 8080)),
    "ftp": int(os.environ.get("FTP_PORT", 2121)),
}

# ── Paths ──
DB_PATH = os.environ.get("DB_PATH", "./data/mirage.db")
COWRIE_LOG_PATH = os.environ.get("COWRIE_LOG_PATH", "./cowrie/logs/cowrie.json")
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "./data/GeoLite2-City.mmdb")

# ── Docker ──
DOCKER_SANDBOX_IMAGE = os.environ.get("DOCKER_SANDBOX_IMAGE", "ubuntu:22.04")

# ── Session ──
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", 300))

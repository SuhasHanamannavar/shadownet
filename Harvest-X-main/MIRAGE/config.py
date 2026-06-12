import os

COWRIE_LOG_PATH = "./cowrie/logs/cowrie.json"
DB_PATH = "./data/mirage.db"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "your-key-here")
PORTS = {"ssh": 2222, "http": 8080, "ftp": 2121}
DOCKER_SANDBOX_IMAGE = "ubuntu:22.04"
GEOIP_DB_PATH = "./data/GeoLite2-City.mmdb"
SESSION_TIMEOUT = 300

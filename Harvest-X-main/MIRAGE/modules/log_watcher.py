import subprocess
import json

def start(callback):
    print("[LogWatcher] Listening to Docker logs...")

    process = subprocess.Popen(
        ["docker", "logs", "-f", "cowrie"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    for line in process.stdout:
        line = line.strip()

        if not line:
            continue

        try:
            # Try parsing JSON logs
            parsed = json.loads(line)

            event = {
                "type": "cowrie",
                "session": parsed.get("session", "unknown"),
                "src_ip": parsed.get("src_ip", "unknown"),
                "command": parsed.get("input", ""),
                "eventid": parsed.get("eventid", ""),
                "raw": parsed
            }

        except:
            # fallback for non-json logs
            event = {
                "type": "cowrie",
                "raw": line
            }

        callback(event)

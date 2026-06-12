import subprocess
import json
import sys

def start(callback):
    try:
        subprocess.run(["docker", "ps"], capture_output=True, text=True, timeout=5)
    except FileNotFoundError:
        print("[LogWatcher] Docker not found. Cowrie log watcher disabled.")
        return
    except Exception as e:
        print(f"[LogWatcher] Docker not available: {e}. Log watcher disabled.")
        return

    print("[LogWatcher] Listening to Docker logs...")

    try:
        process = subprocess.Popen(
            ["docker", "logs", "-f", "cowrie"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
    except Exception as e:
        print(f"[LogWatcher] Failed to start: {e}")
        return

    for line in process.stdout:
        line = line.strip()
        if not line:
            continue

        try:
            parsed = json.loads(line)
            event = {
                "type": "cowrie",
                "session": parsed.get("session", "unknown"),
                "src_ip": parsed.get("src_ip", "unknown"),
                "command": parsed.get("input", ""),
                "eventid": parsed.get("eventid", ""),
                "raw": parsed
            }
        except Exception:
            event = {
                "type": "cowrie",
                "raw": line
            }

        callback(event)

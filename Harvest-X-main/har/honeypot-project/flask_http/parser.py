import json
import os

COWRIE_LOG = "/app/logs/cowrie.json"
HTTP_LOG = "/app/logs/http_logs.json"

def get_recent_logs(limit=200):
    events = []
    
    # Read Cowrie logs
    if os.path.exists(COWRIE_LOG):
        try:
            with open(COWRIE_LOG, "r") as f:
                lines = f.readlines()
                for line in reversed(lines[-limit:]):
                    try:
                        data = json.loads(line)
                        if data.get("eventid") == "cowrie.command.input":
                            events.append({
                                "service": "SSH",
                                "ip": data.get("src_ip", "Unknown"),
                                "timestamp": data.get("timestamp"),
                                "action": f"Command: {data.get('input')}",
                                "raw_command": data.get("input")
                            })
                        elif data.get("eventid") == "cowrie.login.success":
                            events.append({
                                "service": "SSH",
                                "ip": data.get("src_ip", "Unknown"),
                                "timestamp": data.get("timestamp"),
                                "action": f"Login Success: {data.get('username')}/{data.get('password')}",
                                "raw_command": ""
                            })
                    except Exception:
                        pass
        except Exception:
            pass
            
    # Read HTTP Logs
    if os.path.exists(HTTP_LOG):
        try:
            with open(HTTP_LOG, "r") as f:
                lines = f.readlines()
                for line in reversed(lines[-limit:]):
                    try:
                        data = json.loads(line)
                        action_type = data.get('method', '') + " " + data.get('path', '')
                        raw_command = ""
                        # If it's a terminal command, extract it
                        if "/api/terminal/run" in data.get('path', ''):
                            try:
                                d = json.loads(data.get('data', '{}'))
                                if d.get('command'):
                                    action_type = f"Web Shell: {d.get('command')}"
                                    raw_command = d.get('command')
                            except:
                                pass

                        events.append({
                            "service": "HTTP" if "Web Shell" not in action_type else "Web Terminal",
                            "ip": data.get("ip", "Unknown"),
                            "timestamp": data.get("timestamp"),
                            "action": action_type,
                            "raw_command": raw_command
                        })
                    except Exception:
                        pass
        except Exception:
            pass

    # Sort by timestamp descending
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return events[:limit]

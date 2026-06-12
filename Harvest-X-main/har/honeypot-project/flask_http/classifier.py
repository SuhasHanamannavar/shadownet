def classify_events(events):
    # Group by IP
    sessions = {}
    
    for ev in events:
        ip = ev["ip"]
        if ip not in sessions:
            sessions[ip] = {
                "ip": ip,
                "event_count": 0,
                "threat_score": 0,
                "profile": "Unknown",
                "kill_chain": "Recon",
                "services": set(),
                "commands": []
            }
            
        sessions[ip]["event_count"] += 1
        sessions[ip]["services"].add(ev["service"])
        
        cmd = ev.get("raw_command", "")
        if cmd:
            sessions[ip]["commands"].append(cmd)
            
            # Threat Scoring & Profiling
            if any(mal in cmd for mal in ["wget", "curl", "chmod +x", "./", "nc -e", "bash -i"]):
                sessions[ip]["threat_score"] = max(sessions[ip]["threat_score"], 90)
                sessions[ip]["profile"] = "Malware Operator"
                sessions[ip]["kill_chain"] = "Payload Execution"
            elif any(cred in cmd for cred in ["passwd", "shadow", "id", "whoami", "cat .env", "cat config"]):
                sessions[ip]["threat_score"] = max(sessions[ip]["threat_score"], 60)
                if sessions[ip]["profile"] == "Unknown":
                    sessions[ip]["profile"] = "Credential Harvester"
                if sessions[ip]["kill_chain"] in ["Recon", "Unknown"]:
                    sessions[ip]["kill_chain"] = "Privilege Attempt"
            elif any(rec in cmd for rec in ["ls", "pwd", "uname", "top", "ps", "netstat"]):
                sessions[ip]["threat_score"] = max(sessions[ip]["threat_score"], 30)
                if sessions[ip]["profile"] == "Unknown":
                    sessions[ip]["profile"] = "Recon Attacker"
                
    for ip, data in sessions.items():
        data["services"] = list(data["services"])
        if data["threat_score"] == 0:
            data["threat_score"] = 10
            data["profile"] = "Automated Scanner"
        
        if data["threat_score"] < 40:
            data["threat_score_label"] = "Low"
            data["threat_color"] = "#10b981" # Green
        elif data["threat_score"] < 80:
            data["threat_score_label"] = "Medium"
            data["threat_color"] = "#f59e0b" # Yellow
        else:
            data["threat_score_label"] = "High"
            data["threat_color"] = "#ef4444" # Red
            
    return list(sessions.values())

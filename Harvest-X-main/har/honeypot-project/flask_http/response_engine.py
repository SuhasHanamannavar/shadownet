import os
import random

FAKE_FILESYSTEM = {
    ".env": "DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASS=S3cr3tP@ssw0rd!\nAWS_ACCESS_KEY=AKIA1234567890\nAWS_SECRET=FakeSecretKey123",
    "db_backup.sql": "-- MySQL dump\nINSERT INTO users VALUES (1, 'admin', 'admin123');\nINSERT INTO users VALUES (2, 'ceo', 'mypassword1');",
    "id_rsa": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...fake...key...\n-----END RSA PRIVATE KEY-----",
    "notes.txt": "Remember to rotate the DB passwords! - DevOps team\nTODO: fix the command injection on the dashboard.",
    "server.py": "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/')\ndef home(): return 'hello'",
}

def generate_response(command):
    command = command.strip()
    if not command:
        return ""
        
    cmd_parts = command.split()
    base_cmd = cmd_parts[0]
    
    if base_cmd == "ls":
        if "-l" in command or "-la" in command or "-al" in command:
            out = "total 24\n"
            out += "drwxr-xr-x 4 root root 4096 May  4 10:12 .\n"
            out += "drwxr-xr-x 1 root root 4096 May  4 08:00 ..\n"
            for k in FAKE_FILESYSTEM.keys():
                size = len(FAKE_FILESYSTEM[k])
                out += f"-rw-r--r-- 1 root root {size} May  4 10:15 {k}\n"
            return out
        else:
            return " ".join(FAKE_FILESYSTEM.keys()) + " public_html bin var tmp"
            
    elif base_cmd == "cat":
        if len(cmd_parts) > 1:
            filename = cmd_parts[-1]
            return FAKE_FILESYSTEM.get(filename, f"cat: {filename}: No such file or directory")
        return "cat: missing file operand"
        
    elif base_cmd == "pwd":
        return "/var/www/html/backend"
        
    elif base_cmd == "whoami":
        return "root"
        
    elif base_cmd == "id":
        return "uid=0(root) gid=0(root) groups=0(root)"
        
    elif base_cmd in ["wget", "curl"]:
        domain = cmd_parts[-1] if len(cmd_parts) > 1 else "example.com"
        return f"Resolving {domain}... 198.51.100.2\nConnecting to {domain}|198.51.100.2|:80... connected.\nHTTP request sent, awaiting response... 200 OK\nLength: unspecified [text/html]\nSaving to: 'index.html'\n\n[!] ATTENTION: EXTERNAL COMMUNICATION BLOCKED.\n[!] NETWORK CONTAINMENT SIMULATION ACTIVE."
        
    elif base_cmd == "ps":
        return "  PID TTY          TIME CMD\n    1 ?        00:00:01 init\n   42 ?        00:00:00 bash\n   88 ?        00:00:02 python3 app.py\n  108 ?        00:00:00 ps"
        
    elif base_cmd == "netstat":
        return "Active Internet connections (w/o servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 127.0.0.1:3306          127.0.0.1:54321         ESTABLISHED\ntcp        0      0 192.168.1.10:80         203.0.113.5:12345       ESTABLISHED"
        
    elif base_cmd == "uname":
        if "-a" in command:
            return "Linux prod-server-01 5.15.0-101-generic #111-Ubuntu SMP Tue Apr 16 11:21:28 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
        return "Linux"
        
    else:
        return f"bash: {base_cmd}: command not found"

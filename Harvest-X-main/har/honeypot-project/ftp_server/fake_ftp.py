import socket
import threading
import json
import sqlite3
import os
from datetime import datetime

LOG_FILE = "/app/logs/http_logs.json"
DB_FILE = "/app/logs/honeypot.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS ftp_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp TEXT,
            command TEXT,
            argument TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_command(ip, command, argument):
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    log_entry = {
        "service": "ftp_server",
        "ip": ip,
        "timestamp": timestamp,
        "command": command,
        "argument": argument
    }

    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"Error writing to JSON log: {e}")

    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute(
            "INSERT INTO ftp_logs (ip, timestamp, command, argument) VALUES (?, ?, ?, ?)",
            (ip, timestamp, command, argument)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error writing to SQLite: {e}")

def handle_client(conn, addr):
    ip = addr[0]
    conn.sendall(b"220 Welcome to the Fake FTP Server\r\n")
    cwd = "/"
    data_sock = None

    while True:
        try:
            data = conn.recv(1024).decode('utf-8').strip()
            if not data:
                break
                
            parts = data.split(' ', 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            
            log_command(ip, cmd, arg)
            
            if cmd == "USER":
                conn.sendall(b"331 Password required\r\n")
            elif cmd == "PASS":
                conn.sendall(b"230 User logged in\r\n")
            elif cmd == "PWD":
                conn.sendall(f"257 \"{cwd}\" is the current directory\r\n".encode())
            elif cmd == "CWD":
                cwd = arg if arg else "/"
                conn.sendall(b"250 CWD command successful\r\n")
            elif cmd == "SYST":
                conn.sendall(b"215 UNIX Type: L8\r\n")
            elif cmd == "FEAT":
                conn.sendall(b"211-Features:\r\n EPSV\r\n EPRT\r\n PASV\r\n211 End\r\n")
            elif cmd == "TYPE":
                conn.sendall(b"200 Type set to I\r\n")
            elif cmd == "EPSV":
                if data_sock:
                    data_sock.close()
                data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_sock.bind(("0.0.0.0", 0))
                data_sock.listen(1)
                port = data_sock.getsockname()[1]
                conn.sendall(f"229 Entering Extended Passive Mode (|||{port}|)\r\n".encode())
            elif cmd == "PASV":
                if data_sock:
                    data_sock.close()
                data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                data_sock.bind(("0.0.0.0", 0))
                data_sock.listen(1)
                port = data_sock.getsockname()[1]
                p1, p2 = port // 256, port % 256
                local_ip = conn.getsockname()[0]
                ip_str = local_ip.replace(".", ",")
                conn.sendall(f"227 Entering Passive Mode ({ip_str},{p1},{p2})\r\n".encode())
            elif cmd == "LIST":
                if not data_sock:
                    conn.sendall(b"425 Use PORT or PASV first.\r\n")
                    continue
                    
                conn.sendall(b"150 Here comes the directory listing.\r\n")
                
                try:
                    data_conn, data_addr = data_sock.accept()
                    listing = (
                        "drwxr-xr-x    2 root     root         4096 Jan  1  1970 .\r\n"
                        "drwxr-xr-x    2 root     root         4096 Jan  1  1970 ..\r\n"
                        "-rw-r--r--    1 root     root           42 Jan  1  1970 passwords.txt\r\n"
                        "-rw-r--r--    1 root     root         1024 Jan  1  1970 secret_data.csv\r\n"
                    )
                    data_conn.sendall(listing.encode())
                    data_conn.close()
                    conn.sendall(b"226 Directory send OK.\r\n")
                except Exception as e:
                    conn.sendall(b"425 Can't open data connection.\r\n")
                finally:
                    data_sock.close()
                    data_sock = None
            elif cmd == "QUIT":
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"500 Unknown command.\r\n")
        except Exception as e:
            break
            
    if data_sock:
        data_sock.close()
    conn.close()

def main():
    os.makedirs("/app/logs", exist_ok=True)
    init_db()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 2121))
    server.listen(5)
    print("FTP server listening on 2121")
    
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.start()

if __name__ == "__main__":
    main()

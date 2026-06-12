"""
feature_extractor.py
====================
Converts raw honeypot session data (commands + timing) into
numerical feature vectors for the ML classifier.

Features extracted (22 total):
  - 7 command category counts (recon, download, exec, lateral, destruct, auth, misc)
  - 5 command diversity metrics (total, unique, entropy, longest, mean_len)
  - 5 timing features (mean_gap, std_gap, min_gap, max_gap, burst_ratio)
  - 5 risk signal flags (sudo, privesc, python_exec, encoded, output_redirect)
"""

import math
import re

# ── Command taxonomy ──────────────────────────────────────────────────────────
RECON_CMDS = {
    "whoami", "id", "uname", "hostname", "ifconfig", "ip", "netstat",
    "ss", "ps", "top", "cat /etc/passwd", "cat /etc/shadow", "cat /proc",
    "ls", "pwd", "env", "printenv", "find", "locate", "which", "whereis",
    "lsb_release", "uname -a", "uptime", "w", "who", "last", "history",
    "dmesg", "lsmod", "lscpu", "lsmem", "df", "mount", "lsblk"
}

DOWNLOAD_CMDS = {
    "wget", "curl", "fetch", "tftp", "scp", "sftp", "ftp",
    "nc", "ncat", "netcat", "python -c 'import urllib", "pip install"
}

EXEC_CMDS = {
    "chmod", "bash", "sh", "python", "perl", "ruby", "lua",
    "exec", "./", "source", "nohup", "screen", "tmux", "at"
}

LATERAL_CMDS = {
    "ssh", "sshpass", "pssh", "parallel-ssh", "nmap", "masscan",
    "arp", "ping", "traceroute", "msfconsole", "hydra", "medusa"
}

DESTRUCT_CMDS = {
    "rm", "shred", "dd", "mkfs", "fdisk", "> /dev/", "kill",
    "pkill", "reboot", "shutdown", "halt", "iptables -F",
    "echo '' >", "cat /dev/null >"
}

AUTH_CMDS = {
    "sudo", "su ", "passwd", "adduser", "useradd", "usermod",
    "chpasswd", "visudo", "crontab", "at ", "ssh-keygen", "authorized_keys"
}


def _match_category(cmd: str, category_set: set) -> bool:
    cmd_l = cmd.lower().strip()
    return any(cmd_l.startswith(k) or k in cmd_l for k in category_set)


def _shannon_entropy(commands: list) -> float:
    if not commands:
        return 0.0
    freq = {}
    for c in commands:
        freq[c] = freq.get(c, 0) + 1
    n = len(commands)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def extract(session_data: dict) -> list:
    """
    Args:
        session_data: dict with keys:
          - commands: list[str]
          - timings:  list[float]  (seconds between commands, optional)
          - src_ip:   str          (optional, unused in feature vector)

    Returns:
        list of 22 floats ready for sklearn
    """
    commands = session_data.get("commands", []) or []
    timings  = session_data.get("timings",  []) or []

    # ── 1. Category counts (normalized by total commands) ─────────────────────
    n = max(len(commands), 1)
    n_recon    = sum(_match_category(c, RECON_CMDS)    for c in commands) / n
    n_download = sum(_match_category(c, DOWNLOAD_CMDS) for c in commands) / n
    n_exec     = sum(_match_category(c, EXEC_CMDS)     for c in commands) / n
    n_lateral  = sum(_match_category(c, LATERAL_CMDS)  for c in commands) / n
    n_destruct = sum(_match_category(c, DESTRUCT_CMDS) for c in commands) / n
    n_auth     = sum(_match_category(c, AUTH_CMDS)     for c in commands) / n
    n_misc     = 1.0 - (n_recon + n_download + n_exec + n_lateral + n_destruct + n_auth)

    # ── 2. Diversity metrics ───────────────────────────────────────────────────
    total_cmds  = len(commands)
    unique_cmds = len(set(commands))
    entropy     = _shannon_entropy(commands)
    lengths     = [len(c) for c in commands] or [0]
    max_len     = max(lengths)
    mean_len    = sum(lengths) / len(lengths)

    # ── 3. Timing features ────────────────────────────────────────────────────
    if len(timings) >= 2:
        gaps     = timings
        mean_gap = sum(gaps) / len(gaps)
        variance = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
        std_gap  = math.sqrt(variance)
        min_gap  = min(gaps)
        max_gap  = max(gaps)
        # burst ratio: fraction of gaps < 0.5 s
        burst_ratio = sum(1 for g in gaps if g < 0.5) / len(gaps)
    else:
        mean_gap = std_gap = min_gap = max_gap = burst_ratio = 0.0

    # ── 4. Risk signal flags ──────────────────────────────────────────────────
    joined = " ".join(commands).lower()
    has_sudo    = float("sudo" in joined or "su " in joined)
    has_privesc = float(any(k in joined for k in
                            ["chmod +s", "suid", "setuid", "/etc/sudoers", "passwd root"]))
    has_pyexec  = float(any(k in joined for k in
                            ["python -c", "perl -e", "bash -c", "sh -c", "exec("]))
    has_encoded = float(any(k in joined for k in
                            ["base64", "xxd", "openssl enc", "\\x", "%2f"]))
    has_redirect = float(">" in joined or ">>" in joined or "tee " in joined)

    return [
        # Category (7)
        n_recon, n_download, n_exec, n_lateral, n_destruct, n_auth, max(0.0, n_misc),
        # Diversity (5)
        float(total_cmds), float(unique_cmds), entropy, float(max_len), mean_len,
        # Timing (5)
        mean_gap, std_gap, min_gap, max_gap, burst_ratio,
        # Risk flags (5)
        has_sudo, has_privesc, has_pyexec, has_encoded, has_redirect,
    ]

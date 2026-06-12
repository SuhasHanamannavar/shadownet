import json
import time

log_file = "./logs/cowrie.json"

def classify(cmd):
    if "wget" in cmd:
        return "Malware Downloader ⚠️"
    elif "passwd" in cmd:
        return "Recon / Credential Access"
    elif "ls" in cmd:
        return "Exploration"
    else:
        return "Unknown"

with open(log_file, "r") as f:
#    f.seek(0, 2)  # Move to end of file

    while True:
        line = f.readline()

        if not line:
            time.sleep(0.5)
            continue

        try:
            data = json.loads(line)

            if data.get("eventid") == "cowrie.command.input":
                cmd = data.get("input")
                ip = data.get("src_ip")

                print(f"\nIP: {ip}")
                print(f"Command: {cmd}")
                print(f"Type: {classify(cmd)}")

        except:
            pass

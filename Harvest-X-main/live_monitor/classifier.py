"""
classifier.py
=============
Attacker behavior classifier. Extracts features from command history
and classifies the attacker session using a trained RandomForest model
with a robust rule-based fallback.
"""
import os
import pickle
from datetime import datetime

MODEL_PATH = os.path.join(os.path.dirname(__file__), "classifier_model.pkl")

CLASSES = ["Scanner", "Bot", "Script Kiddie", "Human", "APT"]

def extract_features(commands):
    """
    Extracts 8 behavior features from a session's command list.
    commands: list of dicts with keys 'command' and 'timestamp'
    """
    cmd_count = len(commands)
    if cmd_count == 0:
        return [0, 0, 0, 0, 0, 0, 0, 0]

    # Parse timestamps
    parsed_times = []
    for c in commands:
        t = c.get('timestamp')
        if isinstance(t, str):
            try:
                if 'T' in t:
                    parsed_times.append(datetime.fromisoformat(t.replace('Z', '+00:00')))
                else:
                    parsed_times.append(datetime.strptime(t, "%Y-%m-%d %H:%M:%S"))
            except Exception:
                parsed_times.append(datetime.utcnow())
        elif isinstance(t, datetime):
            parsed_times.append(t)
        else:
            parsed_times.append(datetime.utcnow())

    # Sort command sequence by time
    sorted_data = sorted(zip(parsed_times, commands), key=lambda x: x[0])

    # 1. Command count
    # 2. Session duration (seconds)
    duration = 0.0
    if len(sorted_data) > 1:
        duration = (sorted_data[-1][0] - sorted_data[0][0]).total_seconds()

    # 3. Average delay between commands (seconds)
    avg_delay = 0.0
    if cmd_count > 1:
        delays = []
        for i in range(1, len(sorted_data)):
            delays.append((sorted_data[i][0] - sorted_data[i-1][0]).total_seconds())
        avg_delay = sum(delays) / len(delays)

    # Text pattern calculations
    raw_cmds = [c.get('command', '').strip() for c in commands]
    uniq_cmds = len(set(raw_cmds))

    dir_changes = 0
    downloads = 0
    file_access = 0
    expl_depth = 0

    for cmd in raw_cmds:
        cmd_lower = cmd.lower()
        # 5. Directory changes (cd)
        if cmd_lower.startswith('cd ') or cmd_lower == 'cd':
            dir_changes += 1
        # 6. Payload downloads (wget, curl)
        if 'wget' in cmd_lower or 'curl' in cmd_lower:
            downloads += 1
        # 7. File access (cat, nano, etc.)
        if any(kw in cmd_lower for kw in ['cat ', 'nano ', 'vi ', 'vim ', 'less ', 'more ', 'head ', 'tail ']):
            file_access += 1
        # 8. Exploration depth (find, locate, path slashes)
        if 'find ' in cmd_lower or 'locate ' in cmd_lower or '/' in cmd_lower:
            expl_depth += 1

    return [
        cmd_count,
        duration,
        avg_delay,
        uniq_cmds,
        dir_changes,
        downloads,
        file_access,
        expl_depth
    ]

def heuristic_classify(features):
    """
    Fallback rule-based heuristic classification logic.
    Returns: classification, confidence, threat_level, threat_score, interest
    """
    cmd_count, duration, avg_delay, uniq_cmds, dir_changes, downloads, file_access, expl_depth = features

    # 1. Download attempts or rapid execution -> Bot
    if downloads > 0 or (cmd_count >= 3 and avg_delay < 2.0):
        classification = "Bot"
        confidence = min(80 + downloads * 10, 100)
        threat_level = "HIGH"
        threat_score = min(70 + downloads * 15, 100)
        interest = "Malware"
        return classification, confidence, threat_level, threat_score, interest

    # 2. Scanner traits
    if cmd_count <= 4 and duration < 60:
        classification = "Scanner"
        confidence = min(75 + (5 - cmd_count) * 5, 95)
        threat_level = "LOW"
        threat_score = 15
        interest = "Reconnaissance"
        return classification, confidence, threat_level, threat_score, interest

    # 3. APT traits (long duration, slow timing, methodical access)
    if duration > 180 and avg_delay > 10.0 and (expl_depth > 2 or file_access > 2):
        classification = "APT"
        confidence = min(80 + int(duration / 300) * 5, 98)
        threat_level = "CRITICAL"
        threat_score = min(85 + file_access * 2, 100)
        interest = "Credentials" if file_access > dir_changes else "Reconnaissance"
        return classification, confidence, threat_level, threat_score, interest

    # 4. Human traits (regular delays, directory exploration)
    if avg_delay >= 3.0:
        classification = "Human"
        confidence = 85
        threat_level = "MEDIUM"
        threat_score = min(40 + file_access * 5, 80)
        interest = "Credentials" if file_access > dir_changes else "Reconnaissance"
        return classification, confidence, threat_level, threat_score, interest

    # 5. Default -> Script Kiddie
    classification = "Script Kiddie"
    confidence = 70
    threat_level = "MEDIUM"
    threat_score = 50
    interest = "Reconnaissance"
    return classification, confidence, threat_level, threat_score, interest

def classify_session(commands):
    """
    Main classification function. Attempts to load the RF model, otherwise
    falls back to the heuristic rules.
    """
    features = extract_features(commands)
    
    # Try loading local ML model
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                model = pickle.load(f)
            
            # Predict
            pred_idx = int(model.predict([features])[0])
            proba = model.predict_proba([features])[0]
            confidence = int(proba[pred_idx] * 100)
            classification = CLASSES[pred_idx]
            
            # Derive threat level and score based on ML classification and features
            if classification == "APT":
                threat_level = "CRITICAL"
                threat_score = min(85 + features[6] * 2, 100) # file access
            elif classification == "Bot":
                threat_level = "HIGH"
                threat_score = min(70 + features[5] * 15, 100) # downloads
            elif classification == "Script Kiddie":
                threat_level = "MEDIUM"
                threat_score = 55
            elif classification == "Human":
                threat_level = "MEDIUM"
                threat_score = min(40 + features[6] * 5, 80)
            else: # Scanner
                threat_level = "LOW"
                threat_score = 15
                
            # Determine interest
            cmd_count, duration, avg_delay, uniq_cmds, dir_changes, downloads, file_access, expl_depth = features
            if downloads > 0:
                interest = "Malware"
            elif file_access > dir_changes:
                interest = "Credentials"
            elif dir_changes > 0 or expl_depth > 0:
                interest = "Reconnaissance"
            else:
                interest = "Reconnaissance"
                
            return classification, confidence, threat_level, threat_score, interest
        except Exception as e:
            print(f"[Classifier] ML model inference error, using fallback: {e}")
            
    # Fallback to rules
    return heuristic_classify(features)

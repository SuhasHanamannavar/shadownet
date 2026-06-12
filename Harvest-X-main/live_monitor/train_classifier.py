"""
train_classifier.py
===================
Synthesizes a behavior feature dataset and trains a RandomForestClassifier
for classifying attacker sessions into: Scanner, Bot, Script Kiddie, Human, APT.
Saves the trained model as classifier_model.pkl.
"""
import os
import random
import pickle
from sklearn.ensemble import RandomForestClassifier

# Map classes to indices
# CLASSES = ["Scanner", "Bot", "Script Kiddie", "Human", "APT"]
# Indices:   0          1      2                3        4

def generate_synthetic_data(num_samples=150):
    X = []
    y = []

    for _ in range(num_samples):
        # 0. Scanner
        cmd_count = random.randint(1, 4)
        duration = random.uniform(1.0, 45.0)
        avg_delay = random.uniform(2.0, 15.0) if cmd_count > 1 else 0.0
        uniq_cmds = max(1, cmd_count - random.choice([0, 1]))
        dir_changes = random.choice([0, 1]) if cmd_count > 1 else 0
        downloads = 0
        file_access = 0
        expl_depth = random.choice([0, 1])
        X.append([cmd_count, duration, avg_delay, uniq_cmds, dir_changes, downloads, file_access, expl_depth])
        y.append(0)

        # 1. Bot
        cmd_count = random.randint(5, 25)
        duration = random.uniform(2.0, 15.0)
        avg_delay = random.uniform(0.1, 1.5)
        uniq_cmds = random.randint(3, 10)
        dir_changes = random.randint(0, 2)
        downloads = random.randint(1, 5)
        file_access = random.randint(0, 1)
        expl_depth = random.randint(0, 2)
        X.append([cmd_count, duration, avg_delay, uniq_cmds, dir_changes, downloads, file_access, expl_depth])
        y.append(1)

        # 2. Script Kiddie
        cmd_count = random.randint(8, 35)
        duration = random.uniform(30.0, 200.0)
        avg_delay = random.uniform(1.5, 8.0)
        uniq_cmds = random.randint(6, 18)
        dir_changes = random.randint(1, 4)
        downloads = random.randint(0, 2)
        file_access = random.randint(0, 3)
        expl_depth = random.randint(2, 6)
        X.append([cmd_count, duration, avg_delay, uniq_cmds, dir_changes, downloads, file_access, expl_depth])
        y.append(2)

        # 3. Human
        cmd_count = random.randint(8, 45)
        duration = random.uniform(60.0, 800.0)
        avg_delay = random.uniform(4.0, 25.0)
        uniq_cmds = random.randint(7, 25)
        dir_changes = random.randint(2, 8)
        downloads = random.choice([0, 1])
        file_access = random.randint(2, 7)
        expl_depth = random.randint(1, 7)
        X.append([cmd_count, duration, avg_delay, uniq_cmds, dir_changes, downloads, file_access, expl_depth])
        y.append(3)

        # 4. APT
        cmd_count = random.randint(15, 80)
        duration = random.uniform(350.0, 1800.0)
        avg_delay = random.uniform(12.0, 70.0)
        uniq_cmds = random.randint(10, 35)
        dir_changes = random.randint(4, 12)
        downloads = random.randint(1, 3)
        file_access = random.randint(4, 12)
        expl_depth = random.randint(4, 15)
        X.append([cmd_count, duration, avg_delay, uniq_cmds, dir_changes, downloads, file_access, expl_depth])
        y.append(4)

    return X, y

def main():
    print("[Trainer] Generating synthetic attacker behavior dataset...")
    X, y = generate_synthetic_data(200) # 1000 total samples
    
    print(f"[Trainer] Training RandomForest model on {len(X)} samples...")
    model = RandomForestClassifier(n_estimators=100, max_depth=7, random_state=42)
    model.fit(X, y)
    
    model_path = os.path.join(os.path.dirname(__file__), "classifier_model.pkl")
    print(f"[Trainer] Saving model to {model_path}...")
    with open(model_path, "wb") as f:
        pickle.dump(model, f)
        
    print("[Trainer] Model training completed successfully!")

if __name__ == "__main__":
    main()

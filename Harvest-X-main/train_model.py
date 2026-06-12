import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib

print("Loading dataset...")
df = pd.read_csv('cleaned_unsw_nb15.csv')

# Features we can loosely extract from terminal commands
features = ['dur', 'spkts', 'sbytes', 'rate']

# LabelEncoder sorts alphabetically:
# 0: Analysis, 1: Backdoor, 2: DoS, 3: Exploits, 4: Fuzzers, 
# 5: Generic, 6: Normal, 7: Reconnaissance, 8: Shellcode, 9: Worms
def map_to_attacker_type(cat):
    if cat == 6: # Normal
        return 'HUMAN'
    elif cat in [2, 3, 4]: # DoS, Exploits, Fuzzers
        return 'BOT'
    else: # Reconnaissance, Backdoor, etc.
        return 'ADVANCED'

df['target'] = df['attack_cat'].apply(map_to_attacker_type)

X = df[features]
y = df['target']

print("Training RandomForest model on features:", features)
model = RandomForestClassifier(n_estimators=20, max_depth=5, random_state=42)
model.fit(X, y)

print("Saving model...")
joblib.dump(model, 'model.pkl')
print("Model successfully saved to model.pkl!")

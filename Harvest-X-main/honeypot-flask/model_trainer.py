"""
model_trainer.py
================
Trains and saves the ML model (model.pkl) that classifies
HTTP requests as 'normal' (0) or 'attack' (1).

Features used (6 total):
  1. path_length         - length of URL path
  2. payload_length      - length of POST body
  3. has_sql             - SQL injection keywords present
  4. has_xss             - XSS patterns present
  5. has_traversal       - path traversal patterns
  6. param_count         - number of query parameters

Run once: python model_trainer.py
"""

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

np.random.seed(42)

# ── Synthetic training data ────────────────────────────────────────────────
# Each row: [path_len, payload_len, has_sql, has_xss, has_traversal, param_count]
# Label: 0 = normal, 1 = attack

def normal_sample():
    return [
        np.random.randint(5, 30),      # short clean path
        np.random.randint(0, 200),     # small payload
        0,                             # no sql
        0,                             # no xss
        0,                             # no traversal
        np.random.randint(0, 3),       # few params
    ]

def attack_sample():
    attack_type = np.random.choice(['sql', 'xss', 'traversal', 'brute'])
    if attack_type == 'sql':
        return [np.random.randint(30, 200), np.random.randint(100, 2000), 1, 0, 0, np.random.randint(2, 10)]
    elif attack_type == 'xss':
        return [np.random.randint(20, 150), np.random.randint(50, 1500), 0, 1, 0, np.random.randint(1, 8)]
    elif attack_type == 'traversal':
        return [np.random.randint(40, 300), np.random.randint(0, 100), 0, 0, 1, np.random.randint(0, 4)]
    else:  # brute force
        return [np.random.randint(10, 40), np.random.randint(20, 300), 0, 0, 0, np.random.randint(1, 5)]

N = 1000
X = [normal_sample() for _ in range(N)] + [attack_sample() for _ in range(N)]
y = [0] * N + [1] * N

X = np.array(X)
y = np.array(y)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

model = Pipeline([
    ('scaler', StandardScaler()),
    ('clf', RandomForestClassifier(n_estimators=150, max_depth=8, random_state=42))
])

model.fit(X_train, y_train)

print("-- Model Evaluation ----------------------------------")
print(classification_report(y_test, model.predict(X_test), target_names=['Normal', 'Attack']))

joblib.dump(model, 'model.pkl')
print("[✓] model.pkl saved successfully!")

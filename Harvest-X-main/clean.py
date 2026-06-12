import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

# Load dataset
df = pd.read_csv("UNSW_NB15_training-set.csv")

print("Original Shape:", df.shape)

# -----------------------------
# 1. Drop unnecessary columns
# -----------------------------
drop_cols = ["id"] if "id" in df.columns else []
df = df.drop(columns=drop_cols)

# -----------------------------
# 2. Handle missing values
# -----------------------------
df = df.dropna()   # simple for hackathon

# -----------------------------
# 3. Encode categorical columns
# -----------------------------
label_encoders = {}

for col in df.select_dtypes(include=['object']).columns:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    label_encoders[col] = le

# -----------------------------
# 4. Separate features + label
# -----------------------------
# In UNSW dataset:
# 'attack_cat' = type of attack
# 'label' = 0 (normal) / 1 (attack)

X = df.drop(columns=["label", "attack_cat"])
y = df["attack_cat"]

# -----------------------------
# 5. Normalize features
# -----------------------------
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Convert back to DataFrame
X_scaled = pd.DataFrame(X_scaled, columns=X.columns)

# -----------------------------
# 6. Save cleaned data
# -----------------------------
cleaned_df = X_scaled.copy()
cleaned_df["attack_cat"] = y.reset_index(drop=True)

cleaned_df.to_csv("cleaned_unsw_nb15.csv", index=False)

print("Cleaned dataset saved as cleaned_unsw_nb15.csv")
print("Final Shape:", cleaned_df.shape)
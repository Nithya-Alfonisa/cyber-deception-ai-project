print("START")

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

# Load dataset
df = pd.read_csv("data/honeypot_logs.csv")
print("Dataset loaded")

# Encode
le_attack = LabelEncoder()
le_threat = LabelEncoder()

df["attack_type"] = le_attack.fit_transform(df["attack_type"])
df["threat_level"] = le_threat.fit_transform(df["threat_level"])

# Features
X = df[["attack_type", "attempts", "time_step"]]
y = df["threat_level"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Accuracy
accuracy = model.score(X_test, y_test)

print("Model Accuracy:", accuracy)
print("END")

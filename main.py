import pandas as pd
import random

data = []

for i in range(50):
    data.append({
        "ip": f"192.168.0.{random.randint(1,255)}",
        "attack_type": random.choice(["DDoS", "Brute Force", "SQL Injection"]),
        "attempts": random.randint(1, 100),
        "threat_level": random.choice(["Low", "Medium", "High"])
    })

df = pd.DataFrame(data)
df.to_csv("data/honeypot_logs.csv", index=False)

print("Dataset created successfully")
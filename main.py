import pandas as pd
import random
import os

os.makedirs("data", exist_ok=True)

data = []

for i in range(50):  # 50 attack sessions
    attack = random.choice(["DDoS", "Brute Force", "SQL Injection"])
    base_attempts = random.randint(5, 30)

    for t in range(1, 4):  # time steps (1,2,3)
        attempts = base_attempts * t  # increasing pattern

        # LOGIC
        if attempts > 70:
            threat = "High"
        elif attempts > 40:
            threat = "Medium"
        else:
            threat = "Low"

        data.append({
            "ip": f"192.168.0.{random.randint(1,255)}",
            "attack_type": attack,
            "attempts": attempts,
            "time_step": t,
            "threat_level": threat
        })

df = pd.DataFrame(data)
df.to_csv("data/honeypot_logs.csv", index=False)

print("Dataset with time behavior created")

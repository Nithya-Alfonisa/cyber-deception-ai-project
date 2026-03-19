import streamlit as st
import pandas as pd
import random
import time
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder

# ===============================
# 🔥 DARK SOC UI
# ===============================
st.set_page_config(page_title="SOC Threat Dashboard", layout="wide")

st.markdown("""
<style>
.stApp {
    background-color: #0e1117;
    color: white;
}
</style>
""", unsafe_allow_html=True)

# ===============================
# 🔥 SESSION STATE
# ===============================
if "history" not in st.session_state:
    st.session_state.history = []

# ===============================
# TITLE
# ===============================
st.title("🚨 SOC Threat Intelligence Dashboard")

# ===============================
# LOAD DATA
# ===============================
df = pd.read_csv("data/honeypot_logs.csv")

# ===============================
# 🔥 FEATURE ENGINEERING
# ===============================
df = df.sort_values(by="attempts")

df["rolling_attempts"] = df["attempts"].rolling(5, min_periods=1).mean()
df["spike"] = df["attempts"] - df["rolling_attempts"]
df["ip_frequency"] = df.groupby("ip")["ip"].transform("count")

# ===============================
# ENCODING
# ===============================
le_attack = LabelEncoder()
le_threat = LabelEncoder()

df["attack_type"] = le_attack.fit_transform(df["attack_type"])
df["threat_level"] = le_threat.fit_transform(df["threat_level"])

# ===============================
# MODELS
# ===============================
X = df[["attack_type", "attempts", "rolling_attempts", "spike", "ip_frequency"]]
y = df["threat_level"]

clf = RandomForestClassifier()
clf.fit(X, y)

# 🔥 REAL ANOMALY MODEL
iso = IsolationForest(contamination=0.1)
iso.fit(X)

# ===============================
# UI LAYOUT
# ===============================
left, right = st.columns([1, 2])

with left:
    st.subheader("🎯 Attack Input")

    attack = st.selectbox("Attack Type", ["DDoS", "Brute Force", "SQL Injection"])
    attempts = st.slider("Attempts", 1, 100)
    rolling_attempts = st.slider("Avg Attempts", 1, 100)
    ip_frequency = st.slider("IP Frequency", 1, 10)

    predict_btn = st.button("⚡ Predict Threat")
    simulate_btn = st.button("🔥 Simulate Attack")

attack_encoded = le_attack.transform([attack])[0]
spike = attempts - rolling_attempts

input_data = [[attack_encoded, attempts, rolling_attempts, spike, ip_frequency]]

# ===============================
# RIGHT PANEL
# ===============================
with right:
    st.subheader("🚨 Threat Analysis")

    if predict_btn:

        # ===============================
        # PREDICTION
        # ===============================
        prediction = clf.predict(input_data)
        threat = le_threat.inverse_transform(prediction)[0]

        probs = clf.predict_proba(input_data)
        confidence = max(probs[0]) * 100

        # ===============================
        # ANOMALY DETECTION
        # ===============================
        anomaly = iso.predict(input_data)[0]  # -1 = anomaly

        # ===============================
        # RISK SCORE
        # ===============================
        risk_score = (attempts * 0.5) + (spike * 0.3) + (ip_frequency * 5)

        # ===============================
        # KPI BAR
        # ===============================
        c1, c2, c3 = st.columns(3)
        c1.metric("⚠️ Risk Score", f"{risk_score:.2f}")
        c2.metric("🎯 Confidence", f"{confidence:.2f}%")
        c3.metric("📡 Attempts", attempts)

        # ===============================
        # ALERTS
        # ===============================
        st.subheader("🚨 Live Alerts")

        if anomaly == -1:
            st.error("🚨 ANOMALY DETECTED (Isolation Forest)")

        if threat == "High":
            st.error("🔥 HIGH THREAT LEVEL")

        if spike > 30:
            st.warning("⚠️ Sudden Spike Detected")

        if ip_frequency > 5:
            st.warning("⚠️ Repeated Attacker")

        # ===============================
        # EXPLAINABILITY
        # ===============================
        st.subheader("🧠 Why this prediction?")

        st.write(f"- Attack Type Impact: {attack}")
        st.write(f"- High Attempts: {attempts}")
        st.write(f"- Spike Behavior: {spike}")
        st.write(f"- IP Frequency: {ip_frequency}")

        # ===============================
        # HISTORY
        # ===============================
        st.session_state.history.append(attempts)

        # ===============================
        # VISUALS
        # ===============================
        st.subheader("📊 Threat Intelligence")

        col1, col2 = st.columns(2)

        with col1:
            st.line_chart(st.session_state.history)

        with col2:
            labels = le_threat.inverse_transform([0, 1, 2])
            values = probs[0]

            fig, ax = plt.subplots()
            ax.bar(labels, values)
            ax.set_title("Threat Confidence")

            st.pyplot(fig)

    # ===============================
    # 🔥 LIVE SIMULATION
    # ===============================
    if simulate_btn:

        st.subheader("📡 Live Attack Simulation")

        progress = st.progress(0)
        chart = []

        for i in range(1, 6):

            sim_attempts = attempts + i * 10
            sim_rolling = rolling_attempts + i * 5
            sim_spike = sim_attempts - sim_rolling

            sim_input = [[attack_encoded, sim_attempts, sim_rolling, sim_spike, ip_frequency]]

            pred = clf.predict(sim_input)
            probs = clf.predict_proba(sim_input)

            conf = max(probs[0]) * 100
            threat = le_threat.inverse_transform(pred)[0]

            chart.append(conf)

            progress.progress(i * 20)

            st.write(f"Step {i}: Attempts={sim_attempts}")
            st.write(f"Threat: {threat} ({conf:.2f}%)")

            time.sleep(1)

        fig, ax = plt.subplots()
        ax.plot(chart, marker='o')
        ax.set_title("Threat Escalation Over Time")

        st.pyplot(fig)

# ===============================
# FOOTER
# ===============================
st.markdown("---")
st.caption("Industry-Level Cyber Threat Intelligence System")

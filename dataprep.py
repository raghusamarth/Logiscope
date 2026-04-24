import pandas as pd
import numpy as np
import os
import random

df = pd.read_csv("cybersecurity_attacks.csv")

df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')

df['Attack Type'] = df['Attack Type'].fillna("Normal")
df['Action Taken'] = df['Action Taken'].fillna("Allowed")
df['Severity Level'] = df['Severity Level'].fillna("Low")
df['Anomaly Scores'] = df['Anomaly Scores'].fillna(0)

df['Action Taken'] = df['Action Taken'].replace({
    "Ignored": "Allowed",
    "Logged": "Allowed"
})

df['event_type'] = np.where(
    df['Attack Type'].str.lower().isin(["normal", "benign", "none"]),
    "Non-Cyber",
    "Cyber"
)

target_ratio = 0.55  # Non-Cyber
total = len(df)
target_non_cyber = int(total * target_ratio)

current_non_cyber = (df['event_type'] == "Non-Cyber").sum()

if current_non_cyber < target_non_cyber:
    needed = target_non_cyber - current_non_cyber
    idx = df[df['event_type'] == "Cyber"].sample(needed, random_state=42).index
    df.loc[idx, 'event_type'] = "Non-Cyber"
elif current_non_cyber > target_non_cyber:
    excess = current_non_cyber - target_non_cyber
    idx = df[df['event_type'] == "Non-Cyber"].sample(excess, random_state=42).index
    df.loc[idx, 'event_type'] = "Cyber"

df.loc[df['event_type'] == "Non-Cyber", 'Severity Level'] = "Low"

df = df.dropna(subset=['Timestamp'])

os.makedirs("data", exist_ok=True)

firewall_df = df[[
    'Timestamp',
    'Source IP Address',
    'Attack Type',
    'Action Taken',
    'Severity Level',
    'event_type'
]].copy()

# Add port (for drill-down table)
firewall_df['Port'] = [random.choice([80, 443, 22, 21, 8080]) for _ in range(len(firewall_df))]

lb_df = df[['Timestamp', 'Packet Length']].copy()
lb_df['server_id'] = ['S' + str(i % 3 + 1) for i in range(len(lb_df))]
lb_df['request_count'] = lb_df['Packet Length']

lb_df['latency_ms'] = (
    (lb_df['Packet Length'] / lb_df['Packet Length'].max()) * 800 +
    df['Anomaly Scores'] * 400
)

lb_df['event_type'] = df['event_type']

web_df = df[['Timestamp', 'Traffic Type', 'Action Taken', 'Anomaly Scores']].copy()

def map_status(row):
    if row['Action Taken'] == "Blocked":
        return 403
    elif row['Anomaly Scores'] > 0.85:
        return 500
    else:
        return 200

web_df['status_code'] = web_df.apply(map_status, axis=1)

web_df['response_time_ms'] = web_df['status_code'].apply(
    lambda x: 800 if x == 500 else (300 if x == 403 else 150)
)

web_df['event_type'] = df['event_type']

firewall_df.to_csv("data/firewall_logs.csv", index=False)
lb_df.to_csv("data/lb_logs.csv", index=False)
web_df.to_csv("data/web_logs.csv", index=False)

print("✅ Data prepared (clean + realistic 55/45)")
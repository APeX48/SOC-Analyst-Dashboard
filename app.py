import streamlit as st
import pandas as pd

df = pd.read_csv(
    "logs/security_logs.csv"
)

st.title("SOC Dashboard")

c1, c2, c3 = st.columns(3)

c1.metric(
    "Total Alerts",
    len(df)
)

critical = len(
    df[df['severity'] == 'Critical']
)

c2.metric(
    "Critical Alerts",
    critical
)

high = len(
    df[df['severity'] == 'High']
)

c3.metric(
    "High Severity",
    high
)

st.dataframe(df)
st.subheader("Top Suspicious IPs")

suspicious = (
    df['ip']
    .value_counts()
)

st.dataframe(suspicious)
risk = 0

for sev in df["severity"]:

    if sev == "Critical":
        risk += 10

    elif sev == "High":
        risk += 5

    elif sev == "Medium":
        risk += 3

risk = min(risk,100)

st.subheader(
    "Risk Score"
)

st.progress(risk)

st.write(
    f"Current Risk Score: {risk}/100"
)
import plotly.express as px
event_counts = (
    df["event_type"]
    .value_counts()
)

fig = px.bar(
    x=event_counts.index,
    y=event_counts.values,
    title="Security Events"
)

st.plotly_chart(
    fig,
    use_container_width=True
)

# MITRE ATT&CK Mapping

mitre = {
    "Failed Login": "T1110 Brute Force",
    "Port Scan": "T1046 Network Discovery",
    "Malware Detection": "T1204 User Execution"
}

df["MITRE"] = df["event_type"].map(mitre)

st.subheader("MITRE ATT&CK Mapping")

st.dataframe(
    df[["event_type", "MITRE"]]
)

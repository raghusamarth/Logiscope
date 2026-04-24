import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_plotly_events import plotly_events

st.set_page_config(layout="wide", page_title="Cyber Dashboard")

@st.cache_data
def load():
    fw = pd.read_csv("data/firewall_logs.csv")
    lb = pd.read_csv("data/lb_logs.csv")
    web = pd.read_csv("data/web_logs.csv")

    fw['Timestamp'] = pd.to_datetime(fw['Timestamp'])
    lb['Timestamp'] = pd.to_datetime(lb['Timestamp'])
    web['Timestamp'] = pd.to_datetime(web['Timestamp'])

    return fw, lb, web

firewall, lb, web = load()

firewall = firewall.sample(min(3000, len(firewall)))
lb = lb.sample(min(3000, len(lb)))
web = web.sample(min(3000, len(web)))

st.title("🔐 Cyber Monitoring Dashboard")

page = st.selectbox(
    "Select View",
    ["Overview", "Firewall", "Load Balancer", "Web Server"]
)

if page == "Overview":

    combined = pd.concat([
        firewall[['Timestamp','event_type']],
        lb[['Timestamp','event_type']],
        web[['Timestamp','event_type']]
    ])

    cyber = (combined['event_type']=="Cyber").sum()
    non_cyber = (combined['event_type']=="Non-Cyber").sum()

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Events", len(combined))
    c2.metric("🔴 Cyber", cyber)
    c3.metric("🟢 Non-Cyber", non_cyber)

    st.divider()

    counts = combined['event_type'].value_counts().reset_index()
    counts.columns = ['Type','Count']

    fig = px.pie(
        counts,
        names='Type',
        values='Count',
        color='Type',
        color_discrete_map={
            "Cyber": "#ef4444",
            "Non-Cyber": "#22c55e"
        }
    )
    fig.update_layout(title="Overall Event Distribution")

    st.plotly_chart(fig, use_container_width=True)

elif page == "Firewall":

    st.subheader("🛡️ Firewall Analysis")

    action_counts = firewall['Action Taken'].value_counts().reset_index()
    action_counts.columns = ['Action', 'Count']

    fig_pie = px.pie(
        action_counts,
        names='Action',
        values='Count',
        color='Action',
        color_discrete_map={
            "Blocked": "#ef4444",
            "Allowed": "#22c55e"
        }
    )

    fig_pie.update_layout(title="Allowed vs Blocked Traffic")

    selected = plotly_events(fig_pie, click_event=True)

    if selected:
        chosen_action = selected[0]['label']
        filtered = firewall[firewall['Action Taken'] == chosen_action]

        st.subheader(f"{chosen_action} IPs (with Ports)")
        st.dataframe(
            filtered[['Source IP Address', 'Port']].head(20),
            use_container_width=True
        )

    st.divider()

    col1, col2 = st.columns(2)

    attack_counts = firewall['Attack Type'].value_counts().head(6)

    fig_attack = px.bar(
        attack_counts,
        orientation='h',
        title="Top Attack Types",
        color=attack_counts.values,
        color_continuous_scale="Reds"
    )

    col1.plotly_chart(fig_attack, use_container_width=True)

    sev = firewall.groupby(['Severity Level','event_type']).size().reset_index(name='count')

    fig_sev = px.bar(
        sev,
        x='Severity Level',
        y='count',
        color='event_type',
        color_discrete_map={
            "Cyber": "#ef4444",
            "Non-Cyber": "#22c55e"
        },
        title="Severity Distribution"
    )

    col2.plotly_chart(fig_sev, use_container_width=True)

elif page == "Load Balancer":

    st.subheader("⚖️ Traffic Analysis")

    col1, col2 = st.columns(2)

    fig1 = px.histogram(
        lb,
        x='latency_ms',
        nbins=30,
        color_discrete_sequence=["#3b82f6"]
    )
    fig1.update_layout(title="Latency Distribution", bargap=0.3)
    col1.plotly_chart(fig1, use_container_width=True)

    lb_time = lb.groupby(lb['Timestamp'].dt.floor('min')).size()
    fig2 = px.line(lb_time, color_discrete_sequence=["#6366f1"])
    fig2.update_layout(title="Traffic Over Time")
    col2.plotly_chart(fig2, use_container_width=True)

elif page == "Web Server":

    st.subheader("🌐 Web Server Performance")

    col1, col2 = st.columns(2)

    status = web['status_code'].value_counts()
    fig1 = px.bar(status, color=status.values, color_continuous_scale="Blues")
    fig1.update_layout(title="HTTP Status Codes")
    col1.plotly_chart(fig1, use_container_width=True)

    fig2 = px.box(web, x='status_code', y='response_time_ms',
                  color_discrete_sequence=["#8b5cf6"])
    fig2.update_layout(title="Response Time by Status")
    col2.plotly_chart(fig2, use_container_width=True)
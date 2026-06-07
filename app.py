import streamlit as st
import pandas as pd
import plotly.express as px
import os

from detector import load_and_preprocess, train_model, predict
from llm_engine import analyse_incidents
from report_gen import generate_pdf

st.set_page_config(
    page_title="Threat Intelligence AI",
    page_icon="🛡",
    layout="wide"
)

st.title("🛡 AI Threat Intelligence System")
st.caption("Real-time anomaly detection • Gemini-powered incident analysis")

# Sidebar
with st.sidebar:
    st.header("Controls")

    regen = st.button("Re-generate Logs")
    retrain = st.button("Retrain Model")
    run_ai = st.button("Run AI Analysis")

# Generate new logs
if regen:
    from utils.log_parser import generate_logs

    df_new = generate_logs(1000)
    df_new.to_csv("data/network_logs.csv", index=False)
    st.success("New logs generated successfully!")

# Load data and model
df = load_and_preprocess()

if not os.path.exists("models/iso_forest.pkl") or retrain:
    train_model(df)

df = predict(df)

anomalies = df[df["predicted_anomaly"] == True]

# Metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Events", len(df))

with col2:
    st.metric(
        "Anomalies",
        len(anomalies),
        f"{(len(anomalies)/len(df))*100:.1f}%"
    )

with col3:
    critical_count = len(df[df["severity"] == "CRITICAL"])
    st.metric("Critical", critical_count)

with col4:
    st.metric("Unique IPs", df["src_ip"].nunique())

st.divider()

# Chart 1
col_a, col_b = st.columns(2)

with col_a:
    fig1 = px.histogram(
        df,
        x="anomaly_score",
        color="predicted_anomaly",
        title="Anomaly Score Distribution"
    )
    st.plotly_chart(fig1, use_container_width=True)

with col_b:
    severity_counts = (
        anomalies["severity"]
        .value_counts()
        .reset_index()
    )

    severity_counts.columns = ["severity", "count"]

    fig2 = px.pie(
        severity_counts,
        names="severity",
        values="count",
        title="Severity Breakdown"
    )

    st.plotly_chart(fig2, use_container_width=True)

# Timeline Chart
fig3 = px.scatter(
    df,
    x="timestamp",
    y="anomaly_score",
    color="predicted_anomaly",
    size="bytes_sent",
    hover_data=[
        "src_ip",
        "dst_port",
        "status_code"
    ],
    title="Anomaly Timeline"
)

st.plotly_chart(fig3, use_container_width=True)

# Incident Table
st.subheader("Flagged Incidents")

st.dataframe(
    anomalies[
        [
            "timestamp",
            "src_ip",
            "dst_port",
            "status_code",
            "bytes_sent",
            "request_count",
            "severity",
            "anomaly_score"
        ]
    ].sort_values("anomaly_score"),
    use_container_width=True
)

# AI Analysis
if run_ai:
    with st.spinner("Gemini is analysing threats..."):
        analysis, incidents = analyse_incidents(anomalies)

    st.subheader("AI Threat Analysis")

    st.info(
        analysis.get(
            "executive_summary",
            "No summary available."
        )
    )

    col_x, col_y = st.columns(2)

    with col_x:
        st.markdown("### Recommended Actions")

        for action in analysis.get(
            "recommended_actions",
            []
        ):
            st.markdown(f"- {action}")

    with col_y:
        st.markdown(
            f"**Confidence:** {analysis.get('confidence', 'N/A')}"
        )

        st.markdown(
            f"**Attack Vector:** {analysis.get('attack_vector', 'N/A')}"
        )

    pdf_path = generate_pdf(
        analysis,
        len(anomalies)
    )

    with open(pdf_path, "rb") as f:
        st.download_button(
            label="Download Incident Report (PDF)",
            data=f,
            file_name="incident_report.pdf",
            mime="application/pdf"
        )
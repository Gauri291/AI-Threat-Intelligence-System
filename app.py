import streamlit as st
import pandas as pd
import plotly.express as px
import os
import sys

# Add better error handling at app startup
try:
    from detector import load_and_preprocess, train_model, predict
    from llm_engine import analyse_incidents
    from report_gen import generate_pdf
except Exception as e:
    st.error(f"Failed to import modules: {str(e)}")
    st.stop()

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
    
    st.divider()
    st.caption("💡 Tip: If app is slow, logs might be processing. Check console for details.")

# Generate new logs
if regen:
    try:
        with st.spinner("Generating new logs..."):
            from utils.log_parser import generate_logs
            df_new = generate_logs(1000)
            os.makedirs("data", exist_ok=True)
            df_new.to_csv("data/network_logs.csv", index=False)
        st.success("✅ New logs generated successfully!")
    except Exception as e:
        st.error(f"❌ Failed to generate logs: {str(e)}")
        st.stop()

# Load data and model - with progress tracking
try:
    with st.spinner("📊 Loading and preprocessing data..."):
        df = load_and_preprocess()
    
    st.write(f"✅ Loaded {len(df)} network events")
    
except FileNotFoundError:
    st.warning("⚠️ Data file not found! Click 'Re-generate Logs' first.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading data: {str(e)}")
    st.stop()

# Train or load model - with progress tracking
try:
    if not os.path.exists("models/iso_forest.pkl") or retrain:
        with st.spinner("🤖 Training Isolation Forest model..."):
            train_model(df)
        st.write("✅ Model trained successfully")
    
    with st.spinner("🔍 Running anomaly detection..."):
        df = predict(df)
    
    st.write("✅ Predictions complete")
    
except Exception as e:
    st.error(f"❌ Error with model: {str(e)}")
    st.stop()

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

try:
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
except Exception as e:
    st.error(f"Error rendering charts: {str(e)}")

# Timeline Chart
try:
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
except Exception as e:
    st.error(f"Error rendering timeline: {str(e)}")

# Incident Table
st.subheader("Flagged Incidents")

try:
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
except Exception as e:
    st.error(f"Error displaying incidents: {str(e)}")

# AI Analysis
if run_ai:
    if len(anomalies) == 0:
        st.warning("⚠️ No anomalies to analyze. Generate new logs or check data.")
    else:
        try:
            with st.spinner("🔍 Analyzing threats with Gemini AI...\n⏳ This may take 30-60 seconds..."):
                print("[DEBUG] Starting AI analysis...")
                analysis, incidents = analyse_incidents(anomalies)
                print("[DEBUG] AI analysis complete")

            # Check if analysis was successful
            if analysis and "executive_summary" in analysis and analysis["executive_summary"]:
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

                try:
                    pdf_path = generate_pdf(
                        analysis,
                        len(anomalies)
                    )

                    with open(pdf_path, "rb") as f:
                        st.download_button(
                            label="📥 Download Incident Report (PDF)",
                            data=f,
                            file_name="incident_report.pdf",
                            mime="application/pdf"
                        )
                except Exception as pdf_error:
                    st.error(f"PDF generation failed: {str(pdf_error)}")
            else:
                st.warning("⚠️ Analysis returned empty results. Please retry.")
                st.json(analysis)

        except Exception as e:
            st.error(f"❌ Analysis failed: {str(e)}")
            st.info(
                "**Troubleshooting Steps:**\n\n"
                "1. **Check API Key:** Verify `GEMINI_API_KEY` in your `.env` file\n"
                "2. **Check Quota:** Visit https://aistudio.google.com/app/apikeys\n"
                "3. **Check Internet:** Ensure you have internet connectivity\n"
                "4. **Check Logs:** Look at console output for detailed errors\n"
                "5. **Retry:** Wait a moment and try again"
            )
            print(f"[ERROR] {str(e)}", file=sys.stderr)

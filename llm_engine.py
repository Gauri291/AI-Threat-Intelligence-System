import google.generativeai as genai
from dotenv import load_dotenv
import os
import json

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-2.5-flash-lite")
SYSTEM_CONTEXT = """
You are a Senior SOC (Security Operations Center) analyst.
You receive structured network anomaly data and produce concise, actionable threat reports.

Always respond in valid JSON with this schema:
{
  "threat_name": "string",
  "attack_vector": "string",
  "confidence": "HIGH|MEDIUM|LOW",
  "affected_assets": ["list"],
  "recommended_actions": ["list of 3 actions"],
  "executive_summary": "2-sentence plain English summary"
}
"""

def analyse_incidents(anomaly_df, top_n=5):
    critical = anomaly_df[anomaly_df["severity"] == "CRITICAL"].head(top_n)

    if critical.empty:
        critical = anomaly_df[anomaly_df["predicted_anomaly"]].head(top_n)

    incidents_text = critical[
        [
            "timestamp",
            "src_ip",
            "dst_port",
            "status_code",
            "bytes_sent",
            "request_count",
            "anomaly_score",
        ]
    ].to_string(index=False)

    prompt = f"""
{SYSTEM_CONTEXT}

Analyse these network anomalies detected by our ML system:

{incidents_text}

Return ONLY the JSON object. No markdown, no explanation.
"""

    response = model.generate_content(prompt)

    raw = (
        response.text.strip()
        .replace("```json", "")
        .replace("```", "")
        .strip()
    )

    try:
        return json.loads(raw), critical
    except json.JSONDecodeError:
        return {
            "executive_summary": raw,
            "recommended_actions": [],
            "confidence": "LOW"
        }, critical


if __name__ == "__main__":
    from detector import (
        load_and_preprocess,
        train_model,
        predict
    )

    df = load_and_preprocess()

    model_obj, scaler, features = train_model(df)

    df = predict(df, model_obj, scaler, features)

    result, incidents = analyse_incidents(df)

    print(json.dumps(result, indent=2))
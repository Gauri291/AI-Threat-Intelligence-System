import google.generativeai as genai
from dotenv import load_dotenv
import os
import json
import time

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    print("[ERROR] GEMINI_API_KEY not found in .env file!")
else:
    print(f"[DEBUG] API Key found: {api_key[:10]}...")
    genai.configure(api_key=api_key)

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
    """Analyze incidents using Gemini API with timeout"""
    
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

    try:
        print("[DEBUG] Sending request to Gemini API...")
        print(f"[DEBUG] API Key configured: {bool(api_key)}")
        
        start_time = time.time()
        
        # Call with explicit timeout
        response = model.generate_content(
            prompt,
            request_options={"timeout": 30}  # 30 second timeout
        )
        
        elapsed = time.time() - start_time
        print(f"[DEBUG] API response received in {elapsed:.2f}s")
        print(f"[DEBUG] Response length: {len(response.text)} chars")

        raw = (
            response.text.strip()
            .replace("```json", "")
            .replace("```", "")
            .strip()
        )

        parsed = json.loads(raw)
        print("[DEBUG] JSON parsing successful")
        return parsed, critical
        
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON Parse Error: {str(e)}")
        print(f"[DEBUG] Raw response: {response.text[:200]}")
        return {
            "executive_summary": "Analysis completed but response parsing failed.",
            "recommended_actions": ["Review incident manually", "Check API response format"],
            "confidence": "LOW",
            "threat_name": "Parse Error",
            "attack_vector": "Unknown"
        }, critical
        
    except TimeoutError as e:
        print(f"[ERROR] API Timeout (30s exceeded): {str(e)}")
        return {
            "executive_summary": "Gemini API request timed out. Please check your connection or try again.",
            "recommended_actions": ["Check internet connection", "Retry analysis", "Check Gemini quota"],
            "confidence": "LOW",
            "threat_name": "Timeout",
            "attack_vector": "Unknown"
        }, critical
        
    except Exception as e:
        print(f"[ERROR] API Error: {type(e).__name__}: {str(e)}")
        return {
            "executive_summary": f"Gemini API Error: {str(e)}",
            "recommended_actions": [
                "Verify GEMINI_API_KEY in .env file",
                "Check quota at https://aistudio.google.com/app/apikeys",
                "Retry analysis"
            ],
            "confidence": "LOW",
            "threat_name": "API Error",
            "attack_vector": "Unknown"
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

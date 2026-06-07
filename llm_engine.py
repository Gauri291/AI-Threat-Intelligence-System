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
Analyze network anomalies and produce concise threat reports.

Respond ONLY in JSON:
{
  "threat_name": "string",
  "attack_vector": "string",
  "confidence": "HIGH|MEDIUM|LOW",
  "affected_assets": ["IP list"],
  "recommended_actions": ["action 1", "action 2", "action 3"],
  "executive_summary": "1-2 sentence summary"
}
"""

def analyse_incidents(anomaly_df, top_n=3):
    """Analyze incidents using Gemini API with timeout"""
    
    print(f"[DEBUG] Total anomalies: {len(anomaly_df)}")
    
    # Get only top anomalies to reduce data size
    critical = anomaly_df[anomaly_df["severity"] == "CRITICAL"].head(top_n)
    
    if critical.empty:
        critical = anomaly_df.nlargest(top_n, "anomaly_score")
    
    print(f"[DEBUG] Selected {len(critical)} anomalies for analysis")

    # Create minimal incident summary
    incidents_list = []
    for idx, row in critical.iterrows():
        incidents_list.append({
            "ip": str(row["src_ip"]),
            "port": int(row["dst_port"]),
            "status": int(row["status_code"]),
            "score": round(float(row["anomaly_score"]), 2),
            "severity": str(row["severity"])
        })
    
    incidents_json = json.dumps(incidents_list, indent=2)
    
    print(f"[DEBUG] Data size: {len(incidents_json)} bytes")

    prompt = f"""
{SYSTEM_CONTEXT}

Analyze these {len(critical)} detected anomalies:

{incidents_json}

Return ONLY valid JSON. No markdown.
"""

    try:
        print("[DEBUG] Sending request to Gemini API...")
        print(f"[DEBUG] Prompt size: {len(prompt)} bytes")
        print(f"[DEBUG] API Key configured: {bool(api_key)}")
        
        start_time = time.time()
        
        # Call with explicit timeout (shorter for Streamlit)
        response = model.generate_content(
            prompt,
            request_options={"timeout": 20}  # 20 second timeout
        )
        
        elapsed = time.time() - start_time
        print(f"[DEBUG] API response received in {elapsed:.2f}s")
        print(f"[DEBUG] Response length: {len(response.text)} chars")

        raw = (
            response.text.strip()
            .replace("```json", "")
            .replace("```", "")
            .replace("json", "")
            .strip()
        )

        print(f"[DEBUG] Cleaned response: {raw[:100]}...")
        parsed = json.loads(raw)
        print("[DEBUG] JSON parsing successful")
        return parsed, critical
        
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON Parse Error: {str(e)}")
        if 'response' in locals():
            print(f"[DEBUG] Raw response: {response.text[:300]}")
        return {
            "executive_summary": "Analysis returned but couldn't parse response. Please try again.",
            "recommended_actions": ["Retry analysis", "Check incident details manually"],
            "confidence": "LOW",
            "threat_name": "Parse Error",
            "attack_vector": "Unknown",
            "affected_assets": []
        }, critical
        
    except TimeoutError as e:
        print(f"[ERROR] API Timeout (exceeded deadline): {str(e)}")
        return {
            "executive_summary": "API request timed out. Your network or API quota may be limited.",
            "recommended_actions": ["Check internet connection", "Wait and retry", "Check Gemini quota"],
            "confidence": "LOW",
            "threat_name": "Timeout",
            "attack_vector": "Unknown",
            "affected_assets": []
        }, critical
        
    except Exception as e:
        print(f"[ERROR] {type(e).__name__}: {str(e)}")
        import traceback
        traceback.print_exc()
        
        error_msg = str(e)
        if "504" in error_msg or "Deadline" in error_msg:
            summary = "API deadline exceeded. Request took too long. Try again."
        elif "401" in error_msg or "API key" in error_msg.lower():
            summary = "Invalid or missing Gemini API key."
        elif "429" in error_msg or "quota" in error_msg.lower():
            summary = "API quota exceeded. Wait before retrying."
        else:
            summary = f"API Error: {error_msg}"
        
        return {
            "executive_summary": summary,
            "recommended_actions": [
                "Verify .env has GEMINI_API_KEY",
                "Check https://aistudio.google.com/app/apikeys",
                "Retry analysis"
            ],
            "confidence": "LOW",
            "threat_name": "API Error",
            "attack_vector": "Unknown",
            "affected_assets": []
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

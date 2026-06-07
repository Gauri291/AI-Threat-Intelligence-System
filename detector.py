import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os

FEATURES = ["dst_port", "status_code", "bytes_sent", "request_count"]


def load_and_preprocess(path="data/network_logs.csv"):
    df = pd.read_csv(path, parse_dates=["timestamp"])

    df["hour"] = df["timestamp"].dt.hour
    df["is_sensitive_port"] = df["dst_port"].isin([22, 3306, 5432]).astype(int)
    df["error_flag"] = (df["status_code"] >= 400).astype(int)

    return df


def train_model(df):
    features = FEATURES + ["hour", "is_sensitive_port", "error_flag"]

    X = df[features]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42
    )

    model.fit(X_scaled)

    os.makedirs("models", exist_ok=True)

    with open("models/iso_forest.pkl", "wb") as f:
        pickle.dump((model, scaler, features), f)

    print("Model trained and saved.")

    return model, scaler, features


def predict(df, model=None, scaler=None, features=None):

    if model is None:
        with open("models/iso_forest.pkl", "rb") as f:
            model, scaler, features = pickle.load(f)

    X = df[features]
    X_scaled = scaler.transform(X)

    df["anomaly_score"] = model.score_samples(X_scaled)
    df["predicted_anomaly"] = model.predict(X_scaled) == -1

    # Severity Classification
    df["severity"] = "NORMAL"

    # Critical anomalies
    df.loc[
        (df["predicted_anomaly"]) &
        (df["anomaly_score"] <= -0.68),
        "severity"
    ] = "CRITICAL"

    # High anomalies
    df.loc[
        (df["predicted_anomaly"]) &
        (df["anomaly_score"] > -0.68) &
        (df["anomaly_score"] <= -0.60),
        "severity"
    ] = "HIGH"

    # Low anomalies
    df.loc[
        (df["predicted_anomaly"]) &
        (df["anomaly_score"] > -0.60),
        "severity"
    ] = "LOW"

    return df


if __name__ == "__main__":

    os.makedirs("models", exist_ok=True)

    df = load_and_preprocess()

    model, scaler, features = train_model(df)

    df = predict(df, model, scaler, features)

    print("\nDetected Anomalies:\n")

    print(
        df[df["predicted_anomaly"]][
            [
                "timestamp",
                "src_ip",
                "anomaly_score",
                "severity"
            ]
        ].head(10)
    )
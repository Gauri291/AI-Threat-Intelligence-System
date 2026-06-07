import pandas as pd
import random
from faker import Faker
from datetime import datetime, timedelta

fake = Faker()

ATTACK_TYPES = ["SQLi", "XSS", "BruteForce", "PortScan", "DDoS"]
STATUS_CODES = [200, 200, 200, 301, 403, 404, 500, 503]

def generate_logs(n=1000):
    logs = []
    base_time = datetime.now() - timedelta(hours=6)
    for i in range(n):
        is_attack = random.random() < 0.08  # 8% are attacks
        entry = {
            "timestamp": base_time + timedelta(seconds=i*20),
            "src_ip": fake.ipv4() if is_attack else fake.ipv4_private(),
            "dst_port": random.choice([22,80,443,3306,8080]) if is_attack else random.choice([80,443]),
            "status_code": random.choice([403,500,503]) if is_attack else random.choice(STATUS_CODES),
            "bytes_sent": random.randint(50000, 500000) if is_attack else random.randint(200, 5000),
            "request_count": random.randint(200, 2000) if is_attack else random.randint(1, 30),
            "attack_type": random.choice(ATTACK_TYPES) if is_attack else "normal",
            "is_anomaly": is_attack
        }
        logs.append(entry)
    return pd.DataFrame(logs)

if __name__ == "__main__":
    df = generate_logs(1000)
    df.to_csv("data/network_logs.csv", index=False)
    print(f"Generated {len(df)} log entries. Attacks: {df['is_anomaly'].sum()}")
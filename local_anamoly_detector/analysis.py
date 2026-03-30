import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# load + feature preparation
def load_and_prepare(csv_path):
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} packets from {csv_path}")

    # time feature
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["sec_since_midnight"] = (
        df["timestamp"].dt.hour * 3600
        + df["timestamp"].dt.minute * 60
        + df["timestamp"].dt.second
    )

    # encode categorical as ids
    def encode_as_id(df, col, fill_value="MISSING"):
        df[col] = df[col].fillna(fill_value)
        ids, _ = pd.factorize(df[col])
        df[col + "_id"] = ids
        return df

    for col in ["protocol", "src_ip", "dst_ip"]:
        df = encode_as_id(df, col)

    # numeric columns
    for col in ["src_port", "dst_port", "length"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(-1)

    feature_cols = [
        "sec_since_midnight",
        "protocol_id",
        "src_ip_id",
        "dst_ip_id",
        "src_port",
        "dst_port",
        "length",
    ]   


    X = df[feature_cols]
    return df, X



# training on normal data
normal_csv_path = "../packets_normal.csv"  

df_normal, X_normal = load_and_prepare(normal_csv_path)

model = Pipeline(
    steps=[
        ("scaler", StandardScaler()),
        (
            "clf",
            IsolationForest(
                n_estimators=200,
                contamination=0.05,  # expected fraction of anomalies in training
                random_state=42,
                n_jobs=-1,
            ),
        ),
    ]
)

model.fit(X_normal)



# evaluating on your 3 datasets
test_files = {
    "malformed": "../data/extraction/out/packets_malformed.csv",
    "syn_scan": "../data/extraction/out/packets_syn_scan.csv",
    "udp_burst": "../data/extraction/out/packets_udp_burst.csv",
}

for name, path in test_files.items():
    df_test, X_test = load_and_prepare(path)

    # IsolationForest in pipeline is model.named_steps["clf"]
    scores = model.named_steps["clf"].decision_function(
        model.named_steps["scaler"].transform(X_test)
    )
    labels = model.named_steps["clf"].predict(
        model.named_steps["scaler"].transform(X_test)
    )

    # 1 = normal, -1 = anomaly
    df_test["anomaly_label"] = labels        
    df_test["anomaly_score"] = -scores       

    num_packets = len(df_test)
    num_anom = (df_test["anomaly_label"] == -1).sum()

    if num_packets > 0:
        frac_anom = num_anom / num_packets
    else:
        frac_anom = 0

    print(f"\n=== {name} ({path}) ===")
    print(f"Packets: {num_packets}")
    print(f"Anomalies flagged: {num_anom} ({frac_anom:.1%})")

    # inspecting the most anomalous packets
    print("Top 5 most anomalous packets:")
    print(
        df_test.sort_values("anomaly_score", ascending=False)[
            ["timestamp", "src_ip", "dst_ip", "protocol", "length", "anomaly_score", "anomaly_label"]
        ].head()
    )

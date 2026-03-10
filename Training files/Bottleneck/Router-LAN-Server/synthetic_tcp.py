import pandas as pd
import random
import os

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the full path to the CSV
csv_path = os.path.join(script_dir, "3Types-bottleneck-dataset.csv")

# Read the file
df = pd.read_csv(csv_path)
# === Get rows with some TCP activity to base synthetic samples on ===
base_rows = df[df["signal_strength_percent"] > 1.5]
if len(base_rows) < 100:
    base_rows = df.sample(n=200, replace=True)

# === Generate synthetic rows ===
num_rows_to_add = 50
sampled_rows = base_rows.sample(n=num_rows_to_add, replace=True)

#"timestamp", "signal_strength_percent", "channel_congestion_percent", "gateway_ping_ms", "gateway_packet_loss_percent", "crc_error_rate", "label"

# === Build new rows with realistic changes ===
synthetic_rows = []
for _, row in sampled_rows.iterrows():
    new_row = row.copy()
    new_row["signal_strength_percent"] = random.uniform(0, 1.5)
    new_row["channel_congestion_percent"] = random.uniform(0, 2.5)
    new_row["gateway_ping_ms"] = random.uniform(0.1, 3)
    new_row["gateway_packet_loss_percent"] = random.uniform(0, 3)
    new_row["crc_error_rate"] = random.uniform(3, 10)
    new_row["label"] = "CRC"
    synthetic_rows.append(new_row)

# === Create DataFrame from synthetic rows ===
synthetic_df = pd.DataFrame(synthetic_rows)

# === Ensure 'label' exists in original if missing ===
if "label" not in df.columns:
    df["label"] = "normal"

# === Combine and save ===
augmented_df = pd.concat([df, synthetic_df], ignore_index=True)
augmented_df.to_csv("augmented_dataset.csv", index=False)
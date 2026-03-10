import pandas as pd
import random
import os

# Get the directory of the current script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct the full path to the CSV
csv_path = os.path.join(script_dir, "End-user-bottleneck-dataset.csv")

# Read the file
df = pd.read_csv(csv_path)
# === Get rows with some TCP activity to base synthetic samples on ===
base_rows = df[df["avg_tcp_retrans_rate"] > 0.0]
if len(base_rows) < 100:
    base_rows = df.sample(n=200, replace=True)

# === Generate synthetic rows ===
num_rows_to_add = 50
sampled_rows = base_rows.sample(n=num_rows_to_add, replace=True)

# === Build new rows with realistic changes ===
synthetic_rows = []
for _, row in sampled_rows.iterrows():
    new_row = row.copy()
    new_row["avg_tcp_retrans_rate"] = random.uniform(2.5, 5)
    new_row["avg_total_cpu"] = random.uniform(0.9, 2.5)
    new_row["avg_per_core"] = random.uniform(0.8, 2.5)
    new_row["avg_ram_percent"] = random.uniform(0.89, 1.16)
    new_row["avg_swap_percent"] = random.uniform(0.8, 4.5)
    new_row["avg_av_cpu"] = random.uniform(0.0, 3)
    new_row["avg_network_proc_cpu"] = random.uniform(0, 2)
    new_row["label"] = "tcp"
    synthetic_rows.append(new_row)

# === Create DataFrame from synthetic rows ===
synthetic_df = pd.DataFrame(synthetic_rows)

# === Ensure 'label' exists in original if missing ===
if "label" not in df.columns:
    df["label"] = "normal"

# === Combine and save ===
augmented_df = pd.concat([df, synthetic_df], ignore_index=True)
augmented_df.to_csv("augmented_dataset.csv", index=False)


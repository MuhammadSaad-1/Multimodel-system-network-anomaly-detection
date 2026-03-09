import os
import re
import json
import pickle
import joblib
import subprocess
import concurrent.futures
from collections import deque
from xgboost import XGBClassifier

# === Paths & Constants ===
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))
BASELINE_FILE = os.path.join(BASE_DIR, "baseline_metrics_R.json")
MAX_BASELINE_FILE = os.path.join(BASE_DIR, "baseline_max_metrics_R.json")
INIT_COUNT_FILE = os.path.join(BASE_DIR, "init_count.txt")
ROLLING_BUFFER_FILE = os.path.join(BASE_DIR, "rolling_buffer3Types.pkl")
MODEL_PATH = os.path.join(BASE_DIR, "bn_model_13TypesXGB.json")
ENCODER_PATH = os.path.join(BASE_DIR, "label_encoder3Types.pkl")
DOMAIN_KEY = "Router-LAN-Server"
ROLLING_WINDOW_SIZE = 50
MAX_BASELINE_INIT_COUNT = 15
init_count = 0

rolling_buffer = {
    "signal_strength_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "channel_congestion_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "gateway_ping_ms": deque(maxlen=ROLLING_WINDOW_SIZE),
    "gateway_packet_loss_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "crc_error_rate": deque(maxlen=ROLLING_WINDOW_SIZE),
}

def gateway_ip():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True)
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        return match.group(1) if match else None
    except:
        return None

def get_wifi_signal_strength():
    try:
        result = subprocess.run(["nmcli", "-f", "IN-USE,SSID,SIGNAL", "device", "wifi"],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.strip().splitlines()[1:]:
            if line.startswith("*"):
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 3:
                    return 100 - (int(parts[2])), parts[1]
        return -100, "Unknown"
    except Exception:
        return -100, "Unknown"

def get_channel_utilization(ssid_name):
    try:
        result = subprocess.run(["nmcli", "-f", "SSID,CHAN,SIGNAL", "device", "wifi", "list"],
                                capture_output=True, text=True, check=True)
        for line in result.stdout.strip().splitlines()[1:]:
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 3 and parts[0] == ssid_name:
                signal = int(parts[2])
                return min(100, max(0, 100 - signal))
        return 100
    except:
        return 100

def is_wireless():
    try:
        result = subprocess.run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device"], capture_output=True, text=True)
        return any(":wifi" in line for line in result.stdout.strip().splitlines())
    except:
        return False

def get_ping_latency_to_gateway():
    gateway = gateway_ip()
    if not gateway:
        return 0.0
    try:
        result = subprocess.run(["ping", "-c", "1", gateway], capture_output=True, text=True)
        match = re.search(r"rtt .* = [\d.]+/([\d.]+)", result.stdout)
        return float(match.group(1)) if match else 0.0
    except:
        return 0.0

def get_gateway_packet_loss(ping_count=3):
    gateway = gateway_ip()
    if not gateway:
        return 100.0
    try:
        result = subprocess.run(["ping", gateway, "-c", str(ping_count)],
                                capture_output=True, text=True)
        match = re.search(r"(\d+\.?\d*)%\s*packet loss", result.stdout)
        return float(match.group(1)) if match else 100.0
    except:
        return 100.0

def get_crc_error_rate(interface="ens33"):
    try:
        path = f"/sys/class/net/{interface}/statistics/rx_crc_errors"
        return int(open(path).read().strip()) if os.path.exists(path) else -1.0
    except:
        return -1.0

def safe_json_load(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except:
        return {}

def get_max_baseline():
    return safe_json_load(MAX_BASELINE_FILE).get(DOMAIN_KEY, {})

def update_max_baseline():
    global init_count
    full_max = safe_json_load(MAX_BASELINE_FILE)
    max_values = full_max.get(DOMAIN_KEY, {})
    for k in rolling_buffer:
        avg = sum(rolling_buffer[k]) / len(rolling_buffer[k]) if rolling_buffer[k] else 0
        if k not in max_values or avg > max_values[k]:
            max_values[k] = avg

    if init_count == MAX_BASELINE_INIT_COUNT - 1:
        max_values["signal_strength_percent"] = 40
        max_values["channel_congestion_percent"] = 70
        max_values["gateway_ping_ms"] = 150
        max_values["gateway_packet_loss_percent"] = 8
        max_values["crc_error_rate"] = 10

    full_max[DOMAIN_KEY] = max_values
    with open(MAX_BASELINE_FILE, 'w') as f:
        json.dump(full_max, f, indent=2)

def save_baseline():
    max_baseline = get_max_baseline()
    full_data = safe_json_load(BASELINE_FILE)
    baseline = {}
    for k in rolling_buffer:
        avg = sum(rolling_buffer[k]) / len(rolling_buffer[k]) if rolling_buffer[k] else 1.0
        avg = min(avg, max_baseline.get(k, avg))
        baseline[k] = max(1, avg)
    full_data[DOMAIN_KEY] = baseline
    with open(BASELINE_FILE, 'w') as f:
        json.dump(full_data, f, indent=2)

def ensure_baseline_files_exist():
    if not os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, 'w') as f:
            json.dump({DOMAIN_KEY: {
                "signal_strength_percent": 1,
                "channel_congestion_percent": 1,
                "gateway_ping_ms": 1,
                "gateway_packet_loss_percent": 1,
                "crc_error_rate": 1
            }}, f, indent=2)
    if not os.path.exists(MAX_BASELINE_FILE):
        with open(MAX_BASELINE_FILE, 'w') as f:
            json.dump({DOMAIN_KEY: {
                "signal_strength_percent": 1,
                "channel_congestion_percent": 1,
                "gateway_ping_ms": 1,
                "gateway_packet_loss_percent": 1,
                "crc_error_rate": 1
            }}, f, indent=2)

def load_rolling_buffer():
    global rolling_buffer
    if os.path.exists(ROLLING_BUFFER_FILE):
        with open(ROLLING_BUFFER_FILE, 'rb') as f:
            saved = pickle.load(f)
            for k in rolling_buffer:
                rolling_buffer[k] = deque(saved.get(k, []), maxlen=ROLLING_WINDOW_SIZE)

def save_rolling_buffer():
    with open(ROLLING_BUFFER_FILE, 'wb') as f:
        pickle.dump(rolling_buffer, f)

def load_init_count():
    global init_count
    if os.path.exists(INIT_COUNT_FILE):
        try:
            with open(INIT_COUNT_FILE, 'r') as f:
                init_count = int(f.read().strip())
        except:
            init_count = 0

def extract_feature_ratios():
    global init_count
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_main = executor.submit(
            lambda: (
                get_wifi_signal_strength() if is_wireless() else (-1, -1),
                get_channel_utilization(get_wifi_signal_strength()[1]) if is_wireless() else -1,
                get_ping_latency_to_gateway(),
                get_crc_error_rate()
            )
        )

        future_packet_loss = executor.submit(get_gateway_packet_loss, 3)

        (wifi_result, channel_util, ping_latency, crc_rate) = future_main.result()
        packet_loss = future_packet_loss.result()

        values = {
            "signal_strength_percent": wifi_result[0],
            "channel_congestion_percent": channel_util,
            "gateway_ping_ms": ping_latency,
            "gateway_packet_loss_percent": packet_loss,
            "crc_error_rate": crc_rate
        }

    for k in values:
        rolling_buffer[k].append(values[k])

    if init_count < MAX_BASELINE_INIT_COUNT:
        update_max_baseline()
        init_count += 1
        with open(INIT_COUNT_FILE, 'w') as f:
            f.write(str(init_count))

    baseline = safe_json_load(BASELINE_FILE).get(DOMAIN_KEY, {})
    ratios = {
        f"{k}_ratio": values[k] / baseline.get(k, 1.0)
        for k in values
    }

    return ratios

def run_live_classification():
    ensure_baseline_files_exist()
    load_rolling_buffer()
    load_init_count()

    if not os.path.exists(MODEL_PATH):
        return

    model = XGBClassifier()
    model.load_model(MODEL_PATH)
    le = joblib.load(ENCODER_PATH)

    input_order = [
        "signal_strength_percent_ratio",
        "channel_congestion_percent_ratio",
        "gateway_ping_ms_ratio",
        "gateway_packet_loss_percent_ratio",
        "crc_error_rate_ratio"
    ]

    ratios = extract_feature_ratios()
    input_data = [[ratios.get(f, 1.0) for f in input_order]]
    probs = model.predict_proba(input_data)[0]
    top3_indices = probs.argsort()[-3:][::-1]
    top3 = [(le.inverse_transform([i])[0], round(probs[i] * 100, 2)) for i in top3_indices]
    
    if top3[0][0] == "normal":
        save_rolling_buffer()
        save_baseline()
    
    return top3

if __name__ == "__main__":
    run_live_classification()
import re
import os
import json
import pickle
import joblib
import socket
import psutil
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
le = joblib.load(ENCODER_PATH)
default_interface = "Wi-Fi"

# === Rolling buffer ===
rolling_buffer = {
    "signal_strength_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "channel_congestion_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "gateway_ping_ms": deque(maxlen=ROLLING_WINDOW_SIZE),
    "gateway_packet_loss_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "crc_error_rate": deque(maxlen=ROLLING_WINDOW_SIZE),
}

# === Metric functions ===
def get_top_network_interface():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return next((iface for iface, addrs in psutil.net_if_addrs().items()
                     for addr in addrs if addr.family == socket.AF_INET and addr.address == s.getsockname()[0]),
                    default_interface)

def gateway_ip():
    try:
        result = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True)
        match = re.search(r"Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)", result.stdout)
        return match.group(1) if match else None
    except subprocess.CalledProcessError:
        return None

def is_wireless():
    try:
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                capture_output=True, text=True, check=True)
        output = result.stdout.lower()
        return "state" in output and "connected" in output
    except:
        return False

def get_wifi_signal_strength():
    try:
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, check=True)
        output = result.stdout
        signal = re.search(r"^\s*Signal\s*:\s*(\d+)\s*%", output, re.MULTILINE)
        profile = re.search(r"^\s*Profile\s*:\s*(.+)$", output, re.MULTILINE)
        return 100 - (int(signal.group(1))) if signal else -1, profile.group(1).strip() if profile else None
    except:
        return -1, None

def get_channel_utilization(ssid_name):
    try:
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                                capture_output=True, text=True, check=True)
        blocks = re.split(r"SSID \d+ :", result.stdout)
        for block in blocks:
            if ssid_name and ssid_name in block:
                match = re.search(r"Channel Utilization:\s+(\d+)\s+\((\d+)\s*%\)", block)
                return int(match.group(2)) if match else -1
        return -1
    except:
        return -1

def get_ping_latency_to_gateway():
    try:
        gateway_ = gateway_ip()
        if not gateway_:
            return -1
        result = subprocess.run(["ping", "-n", "1", gateway_],
                                capture_output=True, text=True)
        match = re.search(r"Average = (\d+)\s*ms", result.stdout)
        return float(match.group(1)) if match else -1
    except:
        return -1

def get_gateway_packet_loss(count=5):
    try:
        gateway = gateway_ip()
        if not gateway:
            return 100.0
        result = subprocess.run(["ping", gateway, "-n", str(count)],
                                capture_output=True, text=True)
        match = re.search(r"(\d+)%\s*loss", result.stdout)
        return float(match.group(1)) if match else 100.0
    except:
        return 100.0

def get_crc_error_rate():
    try:
        powershell_cmd = "Get-Counter -Counter '\\Network Interface(*)\\Packets Received Errors'"
        output = subprocess.check_output(["powershell", "-Command", powershell_cmd], text=True)
        values = [float(line.strip()) for line in output.splitlines() if line.strip().replace('.', '', 1).isdigit()]
        return round(sum(values), 3) if values else -1.0
    except:
        return -1.0

# === Utility & Baseline ===
def safe_json_load(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except:
        return {}

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
        with open(INIT_COUNT_FILE, 'r') as f:
            init_count = int(f.read().strip())

def update_max_baseline():
    global init_count
    full_max = safe_json_load(MAX_BASELINE_FILE)
    max_values = full_max.get(DOMAIN_KEY, {})

    for k in rolling_buffer:
        avg = sum(rolling_buffer[k]) / len(rolling_buffer[k]) if rolling_buffer[k] else 0
        if k not in max_values or avg > max_values[k]:
            max_values[k] = avg

    if init_count == MAX_BASELINE_INIT_COUNT - 1:
        max_values.update({
            "signal_strength_percent": 40,
            "channel_congestion_percent": 70,
            "gateway_ping_ms": 150,
            "gateway_packet_loss_percent": 8,
            "crc_error_rate": 10
        })

    full_max[DOMAIN_KEY] = max_values
    with open(MAX_BASELINE_FILE, 'w') as f:
        json.dump(full_max, f, indent=2)

def get_max_baseline():
    return safe_json_load(MAX_BASELINE_FILE).get(DOMAIN_KEY, {})

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
                "signal_strength_percent": 1.0,
                "channel_congestion_percent": 1.0,
                "gateway_ping_ms": 1.0,
                "gateway_packet_loss_percent": 1.0,
                "crc_error_rate": 1.0
            }}, f, indent=2)
    if not os.path.exists(MAX_BASELINE_FILE):
        with open(MAX_BASELINE_FILE, 'w') as f:
            json.dump({DOMAIN_KEY: {
                "signal_strength_percent": 1.0,
                "channel_congestion_percent": 1.0,
                "gateway_ping_ms": 1.0,
                "gateway_packet_loss_percent": 1.0,
                "crc_error_rate": 1.0
            }}, f, indent=2)

'''
def extract_feature_ratios():
    global init_count

    def timed_call(func, *args, **kwargs):
        """Run a function and return its result and execution time."""
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        return result, end - start

    if is_wireless():
        (signal_strength, ssid), t1 = timed_call(get_wifi_signal_strength)
        channel_util, t2 = timed_call(get_channel_utilization, ssid)
    else:
        signal_strength, channel_util = -1, -1
        t1, t2 = 0, 0

    gateway_ping, t3 = timed_call(get_ping_latency_to_gateway)
    gateway_loss, t4 = timed_call(get_gateway_packet_loss, 3)
    crc_error, t5 = timed_call(get_crc_error_rate)

    values = {
        "signal_strength_percent": signal_strength,
        "channel_congestion_percent": channel_util,
        "gateway_ping_ms": gateway_ping,
        "gateway_packet_loss_percent": gateway_loss,
        "crc_error_rate": crc_error
    }

    timings = {
        "get_wifi_signal_strength": t1,
        "get_channel_utilization": t2,
        "get_ping_latency_to_gateway": t3,
        "get_gateway_packet_loss": t4,
        "get_crc_error_rate": t5
    }

    print("Values:", values)
    print("Function timings (seconds):", timings)

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
    top3 = [(le.inverse_transform([i])[0], round(probs[i]*100, 2)) for i in top3_indices]
    
    if top3[0][0] == "normal":
        save_rolling_buffer()
        save_baseline()
    
    return top3

# === Entry Point ===
if __name__ == "__main__":
    run_live_classification()
'''

# === Feature Extraction ===
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

# === Entry Point ===
if __name__ == "__main__":
    run_live_classification()
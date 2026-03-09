import os
import json
import time
import pickle
import joblib
import socket
import psutil
import subprocess
import concurrent.futures
from datetime import datetime
from collections import deque
from xgboost import XGBClassifier

# === Paths & Constants ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
BASELINE_FILE = os.path.join(BASE_DIR, "baseline_metrics_EU.json")
MAX_BASELINE_FILE = os.path.join(BASE_DIR, "baseline_max_metrics_EU.json")
INIT_COUNT_FILE = os.path.join(BASE_DIR, "init_count.txt")
ROLLING_BUFFER_FILE = os.path.join(BASE_DIR, "rolling_buffer_End.pkl")
MODEL_PATH = os.path.join(BASE_DIR, "bn_model_1EndUserXGB.json")
ENCODER_PATH = os.path.join(BASE_DIR, "label_encoder.pkl")
TSHARK_PATH = os.path.join(BASE_DIR, '..', 'Wireshark', 'tshark.exe')
DOMAIN_KEY = "end_user_device"
ROLLING_WINDOW_SIZE = 50
MAX_BASELINE_INIT_COUNT = 15
SAMPLE_DURATION = 3
init_count = 0
default_interface = "WiFi"
le = joblib.load(ENCODER_PATH)

# === Metrics State ===
rolling_buffer = {
    "avg_total_cpu": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_per_core": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_ram_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_swap_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_av_cpu": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_network_proc_cpu": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_tcp_retrans_rate": deque(maxlen=ROLLING_WINDOW_SIZE)
}

# === Utility Functions ===
def safe_json_load(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def load_init_count():
    global init_count
    if os.path.exists(INIT_COUNT_FILE):
        try:
            with open(INIT_COUNT_FILE, 'r') as f:
                init_count = int(f.read().strip())
        except Exception:
            init_count = 0

def get_top_network_interface():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]

    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                return iface_name
    return default_interface

# ===== monitoring functions ======

def get_cpu_usage():
    total_cpu = psutil.cpu_percent(interval=None)
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    return {"total_cpu": total_cpu, "per_core": per_core}

def get_memory_usage():
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {"ram_percent": mem.percent, "swap_percent": swap.percent}

def get_tcp_retransmissions(interface, duration=3):
    try:
        # Capture packets with tshark for the specified duration
        cmd = [
            TSHARK_PATH,
            "-i", interface,
            "-a", f"duration:{duration}",
            "-Y", "tcp",
            "-T", "fields",
            "-e", "tcp.analysis.retransmission"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        lines = result.stdout.strip().split('\n')
        total_tcp = len(lines)
        retransmissions = sum(1 for line in lines if line.strip() != '')

        rate = (retransmissions / total_tcp * 100) if total_tcp > 0 else 0.0
        return round(rate, 2)

    except subprocess.CalledProcessError as e:
        print(f"[x] tshark error: {e.stderr}")
        return 0.0
    except Exception as e:
        print(f"[x] Unexpected error during tshark capture: {e}")
        return 0.0
    
def get_top_network_process_by_cpu():
    process_cpu_map = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc.cpu_percent(interval=None)
        except Exception:
            continue
    time.sleep(1)
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            conns = proc.net_connections(kind='inet')
            if any(conn.status == psutil.CONN_ESTABLISHED for conn in conns):
                cpu = proc.cpu_percent(interval=None)
                if cpu > 0:
                    process_cpu_map[proc.name()] = process_cpu_map.get(proc.name(), 0.0) + cpu
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sum(process_cpu_map.values()) if process_cpu_map else 0.0

def get_top_antivirus_by_cpu():
    av_keywords = ["av", "defender", "security", "kaspersky", "mcafee", "norton", "eset", "bitdefender", "msmpeng"]
    av_procs = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if any(name.startswith(keyword) for keyword in av_keywords):
                proc.cpu_percent(interval=None)
                av_procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    time.sleep(1)
    return max(sum(proc.cpu_percent(interval=None) for proc in av_procs if proc.is_running()), 0.0)

# === Persistence ===
def save_rolling_buffer():
    with open(ROLLING_BUFFER_FILE, 'wb') as f:
        pickle.dump(rolling_buffer, f)

def load_rolling_buffer():
    global rolling_buffer
    if os.path.exists(ROLLING_BUFFER_FILE):
        with open(ROLLING_BUFFER_FILE, 'rb') as f:
            saved_buffer = pickle.load(f)
            for k in rolling_buffer:
                rolling_buffer[k] = deque(saved_buffer.get(k, []), maxlen=ROLLING_WINDOW_SIZE)

# === Max Baseline Functions (Updated) ===
def update_max_baseline():
    #hardcoded values at the moment
    
    global init_count
    full_max = safe_json_load(MAX_BASELINE_FILE)
    max_values = full_max.get(DOMAIN_KEY, {})
    if max_values == {}:
        max_values = {
            "avg_total_cpu": 0,
            "avg_per_core": 0,
            "avg_ram_percent": 0,
            "avg_swap_percent": 0,
            "avg_av_cpu": 0,
            "avg_network_proc_cpu": 0,
            "avg_tcp_retrans_rate": 0
        }
    
    # Apply scaling only during initialization phase
    #if init_count == MAX_BASELINE_INIT_COUNT - 1:
    if "avg_total_cpu" in max_values:
        max_values["avg_total_cpu"] = 75
    if "avg_per_core" in max_values:
        max_values["avg_per_core"] = 75
    if "avg_ram_percent" in max_values:
        max_values["avg_ram_percent"] = 80
    if "avg_swap_percent" in max_values:
        max_values["avg_swap_percent"] = 30
    if "avg_av_cpu" in max_values:
        max_values["avg_av_cpu"] = 100
    if "avg_network_proc_cpu" in max_values:
        max_values["avg_network_proc_cpu"] = 70
    if "avg_tcp_retrans_rate" in max_values:
        max_values["avg_tcp_retrans_rate"] = 10

    full_max[DOMAIN_KEY] = max_values
    with open(MAX_BASELINE_FILE, 'w') as f:
        json.dump(full_max, f, indent=2)

def get_max_baseline():
    full_max = safe_json_load(MAX_BASELINE_FILE)
    if DOMAIN_KEY not in full_max:
        full_max[DOMAIN_KEY] = {}
        with open(MAX_BASELINE_FILE, 'w') as f:
            json.dump(full_max, f, indent=2)
    return full_max[DOMAIN_KEY]

def save_baseline():
    max_baseline = get_max_baseline()
    full_data = safe_json_load(BASELINE_FILE)
    baseline = {}
    for k in rolling_buffer:
        avg = sum(rolling_buffer[k]) / len(rolling_buffer[k]) if rolling_buffer[k] else 1.0
        if k in max_baseline:
            avg = min(avg, max_baseline[k])
        baseline[k] = max(2, avg)

    full_data[DOMAIN_KEY] = baseline
    with open(BASELINE_FILE, 'w') as f:
        json.dump(full_data, f, indent=2)
    #with open(MAX_BASELINE_FILE, 'w') as f:
    #    json.dump(max_baseline, f, indent=2)

def ensure_baseline_files_exist():
    if not os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, 'w') as f:
            json.dump({DOMAIN_KEY: {
                "avg_total_cpu": 0,
                "avg_per_core": 0,
                "avg_ram_percent": 0,
                "avg_swap_percent": 0,
                "avg_av_cpu": 0,
                "avg_network_proc_cpu": 0,
                "avg_tcp_retrans_rate": 0
            }}, f, indent=2)

    if not os.path.exists(MAX_BASELINE_FILE):
        with open(MAX_BASELINE_FILE, 'w') as f:
            json.dump({DOMAIN_KEY: {
                "avg_total_cpu": 0,
                "avg_per_core": 0,
                "avg_ram_percent": 0,
                "avg_swap_percent": 0,
                "avg_av_cpu": 0,
                "avg_network_proc_cpu": 0,
                "avg_tcp_retrans_rate": 0
            }}, f, indent=2)

def extract_features(cpu_stats, mem_stats, av_cpu, net_cpu, tcp_retrans):
    return {
        "avg_total_cpu": cpu_stats["total_cpu"],
        "avg_per_core": sum(cpu_stats["per_core"]) / len(cpu_stats["per_core"]),
        "avg_ram_percent": mem_stats["ram_percent"],
        "avg_swap_percent": mem_stats["swap_percent"],
        "avg_av_cpu": av_cpu,
        "avg_network_proc_cpu": net_cpu,
        "avg_tcp_retrans_rate": tcp_retrans
    }

def update_and_persist_state(features):
    global init_count

    # Update rolling buffer
    for k, v in features.items():
        rolling_buffer[k].append(v)

    # Initialize baseline if needed
    if init_count < MAX_BASELINE_INIT_COUNT:
        update_max_baseline()
        init_count += 1
        with open(INIT_COUNT_FILE, 'w') as f:
            f.write(str(init_count))
            
def extract_feature_ratios(cpu_stats, mem_stats, av_cpu, net_cpu, tcp_retrans):
    features = extract_features(cpu_stats, mem_stats, av_cpu, net_cpu, tcp_retrans)
    update_and_persist_state(features)

    baseline_values = safe_json_load(BASELINE_FILE).get(DOMAIN_KEY, {})
    ratios = {
        k.replace("avg_", "") + "_ratio": features[k] / baseline_values[k]
        if baseline_values.get(k, 0) > 0 else 1.0
        for k in features
    }
    return ratios

def thread1():
    cpu_stats = get_cpu_usage()
    mem_stats = get_memory_usage()
    av_cpu = get_top_antivirus_by_cpu()
    net_cpu = get_top_network_process_by_cpu()
    
    return cpu_stats, mem_stats, av_cpu, net_cpu

def thread2():
    interface = get_top_network_interface()
    tcp = get_tcp_retransmissions(interface)
    return tcp


def run_live_classification():
    ensure_baseline_files_exist()
    model = XGBClassifier()
    model.load_model(MODEL_PATH)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future1 = executor.submit(thread1)
        future2 = executor.submit(thread2)

        result1 = future1.result()
        result2 = future2.result()
    
    cpu_stats, mem_stats, av_cpu, net_cpu = result1
    tcp_retrans = result2

    features = extract_features(cpu_stats, mem_stats, av_cpu, net_cpu, tcp_retrans)
    update_and_persist_state(features)
    ratios = extract_feature_ratios(cpu_stats, mem_stats, av_cpu, net_cpu, tcp_retrans)
    
    input_order = [
        "total_cpu_ratio",
        "per_core_ratio",
        "ram_percent_ratio",
        "swap_percent_ratio",
        "av_cpu_ratio",
        "network_proc_cpu_ratio",
        "tcp_retrans_rate_ratio"
    ]

    input_data = [[ratios[feature] for feature in input_order]]
    probs = model.predict_proba(input_data)[0]
    top_indice = probs.argsort()[-3:][::-1]  
    top3 = [(le.inverse_transform([i])[0], round(probs[i]*100, 2)) for i in top_indice]
    
    if top3[0][0] == "normal":
        save_rolling_buffer()
        save_baseline()
    
    return top3

if __name__ == "__main__":
    while True:
        start = datetime.now()
        print(run_live_classification())
        print(datetime.now() - start)
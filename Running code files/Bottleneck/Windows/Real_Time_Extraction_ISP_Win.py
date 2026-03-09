import re
import os
import json
import time
import pickle
import joblib
import socket
import psutil
import subprocess
import statistics
import concurrent.futures
from collections import deque
from datetime import datetime
from xgboost import XGBClassifier
from scapy.all import IP, ICMP, sr1, conf

# === Paths & Constants ===
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__)))
BASELINE_FILE = os.path.join(BASE_DIR, "baseline_metrics_ISP.json")
MAX_BASELINE_FILE = os.path.join(BASE_DIR, "baseline_max_metrics_ISP.json")
INIT_COUNT_FILE = os.path.join(BASE_DIR, "init_count.txt")
ROLLING_BUFFER_FILE = os.path.join(BASE_DIR, "rolling_buffer_ISP.pkl")
MODEL_PATH = os.path.join(BASE_DIR, "bn_model_1ISPXGB.json") 
ENCODER_PATH = os.path.join(BASE_DIR, "label_encoderISP.pkl")
DOMAIN_KEY = "ISP"
ROLLING_WINDOW_SIZE = 50
MAX_BASELINE_INIT_COUNT = 15
#SAMPLE_DURATION = 10
init_count = 0
le = joblib.load(ENCODER_PATH)
default_interface = "WiFi"  # Default network interface name

# === Rolling buffer ===
rolling_buffer = {
    "packet_loss": deque(maxlen=ROLLING_WINDOW_SIZE),
    "latency_jitter": deque(maxlen=ROLLING_WINDOW_SIZE),
    "dns_resolve_time": deque(maxlen=ROLLING_WINDOW_SIZE),
    "hop_count": deque(maxlen=ROLLING_WINDOW_SIZE),
    "per_hop_rtt": deque(maxlen=ROLLING_WINDOW_SIZE),
}

# == Monitoring Functions ===
def analyze_ping(target="8.8.8.8", count=3):
    try:
        result = subprocess.run(["ping", "-n", str(count), target], capture_output=True, text=True, check=True)
        output = result.stdout
        packet_loss_match = re.search(r'(\d+(?:\.\d+)?)% loss', output)
        packet_loss = float(packet_loss_match.group(1)) if packet_loss_match else 0.0
        rtts = [float(rtt) for rtt in re.findall(r'time=(\d+(?:\.\d+)?)', output)]
        jitter = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
        return {"packet_loss": packet_loss, "latency_jitter": jitter}
    except Exception:
        return {"packet_loss": 100.0, "latency_jitter": 0.0}

def dns_resolve_time(domains=['google.com', 'cloudflare.com', 'openai.com']):
    times = []
    for domain in domains:
        start = time.time()
        try:
            socket.gethostbyname(domain)
        except Exception:
            continue
        end = time.time()
        times.append((end - start) * 1000)
    return round(statistics.mean(times), 2) if times else 1000.0

def traceroute_analysis(host='8.8.8.8', max_hops=10, timeout=1):
    rtts = []
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=host, ttl=ttl) / ICMP()
        start = time.time()
        reply = sr1(pkt, verbose=0, timeout=timeout)
        end = time.time()
        if reply is None:
            rtts.append(-1)
        else:
            rtts.append((end - start) * 1000)
            if reply.src == host:
                break
    valid_rtts = [r for r in rtts if r >= 0]
    return {
        "hop_count": len(rtts),
        "per_hop_rtt": round(statistics.mean(valid_rtts), 2) if valid_rtts else 0.0
    }

# === Utility FUnctions ===
def safe_json_load(path):
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}

def load_rolling_buffer():
    global rolling_buffer
    if os.path.exists(ROLLING_BUFFER_FILE):
        with open(ROLLING_BUFFER_FILE, 'rb') as f:
            saved = pickle.load(f)
            for k in rolling_buffer:
                rolling_buffer[k] = deque(saved.get(k, []), maxlen=ROLLING_WINDOW_SIZE)

def load_init_count():
    global init_count
    if os.path.exists(INIT_COUNT_FILE):
        try:
            with open(INIT_COUNT_FILE, 'r') as f:
                init_count = int(f.read().strip())
        except Exception:
            init_count = 0
            
def save_rolling_buffer():
    with open(ROLLING_BUFFER_FILE, 'wb') as f:
        pickle.dump(rolling_buffer, f)

def get_top_network_interface():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]

    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                return iface_name
    return default_interface

# === Baseline Functions ===
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

    # Apply scaling only during initialization phase
    if init_count == MAX_BASELINE_INIT_COUNT - 1:
        if "packet_loss" in max_values:
            max_values["packet_loss"] = 8
        if "latency_jitter" in max_values:
            max_values["latency_jitter"] = 80
        if "dns_resolve_time" in max_values:
            max_values["dns_resolve_time"] = 80
        #if "download_ratio" in max_values:
            #max_values["download_ratio"] *= 2
        #if "upload_ratio" in max_values:
            #max_values["upload_ratio"] *= 2
        if "hop_count" in max_values:
            max_values["hop_count"] = 10
        if "per_hop_rtt" in max_values:
            max_values["per_hop_rtt"] = 80

    full_max[DOMAIN_KEY] = max_values
    with open(MAX_BASELINE_FILE, 'w') as f:
        json.dump(full_max, f, indent=2)

def save_baseline():
    max_baseline = get_max_baseline()
    
    full_data = safe_json_load(BASELINE_FILE)

    baseline = {}
    for k in rolling_buffer:
        avg = sum(rolling_buffer[k]) / len(rolling_buffer[k]) if rolling_buffer[k] else 1.0
        if k in max_baseline:
            avg = min(avg, max_baseline[k])
        baseline[k] = max(1, avg)

    full_data[DOMAIN_KEY] = baseline
    with open(BASELINE_FILE, 'w') as f:
        json.dump(full_data, f, indent=2)
    #with open(MAX_BASELINE_FILE, 'w') as f:
    #    json.dump(max_baseline, f, indent=2)

def ensure_baseline_files_exist():
    if not os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, 'w') as f:
            json.dump({DOMAIN_KEY: {
                "packet_loss": 1,
                "latency_jitter": 1,
                "dns_resolve_time": 1,
                "hop_count": 1,
                "per_hop_rtt": 1
            }}, f, indent=2)
    if not os.path.exists(MAX_BASELINE_FILE):
        with open(MAX_BASELINE_FILE, 'w') as f:
            json.dump({DOMAIN_KEY: {
                "packet_loss": 1,
                "latency_jitter": 1,
                "dns_resolve_time": 1,
                "hop_count": 1,
                "per_hop_rtt": 1
            }}, f, indent=2)

# === Live Ratio Extraction ===
def extract_feature_ratios(values):
    global init_count
    conf.route.resync()

    for k in values:
        rolling_buffer[k].append(values[k])

    if init_count < MAX_BASELINE_INIT_COUNT:
        update_max_baseline()
        init_count += 1
        with open(INIT_COUNT_FILE, 'w') as f:
            f.write(str(init_count))

    baseline = safe_json_load(BASELINE_FILE).get(DOMAIN_KEY, {})
    ratios = {
        f"{k}_ratio": values[k] / baseline[k] if baseline.get(k) else 1.0
        for k in values
    }

    return ratios

# === Classification ===
def run_live_classification():
    ensure_baseline_files_exist()
    load_rolling_buffer()
    conf.iface = get_top_network_interface()

    model = XGBClassifier()
    model.load_model(MODEL_PATH)

    input_order = [
        "packet_loss_ratio",
        "latency_jitter_ratio",
        "dns_resolve_time_ratio",
        "hop_count_ratio",
        "per_hop_rtt_ratio"
    ]
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future1 = executor.submit(analyze_ping)
        future2 = executor.submit(dns_resolve_time)
        future3 = executor.submit(traceroute_analysis)
        
        ping = future1.result()
        dns_time = future2.result()
        trace = future3.result()

    values = {
        "packet_loss": ping["packet_loss"],
        "latency_jitter": ping["latency_jitter"],
        "dns_resolve_time": dns_time,
        "hop_count": trace["hop_count"],
        "per_hop_rtt": trace["per_hop_rtt"]
    }
    
    ratios = extract_feature_ratios(values)
    
    
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
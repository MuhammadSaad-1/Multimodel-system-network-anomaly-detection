import csv
import time
import threading
import os
import json
import pickle
import subprocess
import re
from scapy.all import IP, ICMP, sr1
import time
import statistics
import socket
import speedtest
from datetime import datetime
from collections import deque

# === Constants ===
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILE = os.path.join(BASE_DIR, "ISP", "ISP-bottleneck-dataset.csv")
BASELINE_FILE = os.path.join(BASE_DIR, "baseline_metrics.json")
MAX_BASELINE_FILE = os.path.join(BASE_DIR, "max_baseline_metrics.json")
INIT_COUNT_FILE = os.path.join(BASE_DIR, "init_count.txt")
ROLLING_BUFFER_FILE = os.path.join(BASE_DIR, "rolling_buffer.pkl")
DOMAIN_KEY = "ISP"
LOG_INTERVAL = 3  # In seconds. Time between consecutive metric collection cycles.
ROLLING_WINDOW_SIZE = 50
MAX_BASELINE_INIT_COUNT = 15

# === Globals ===
is_logging = False
current_label = "Normal"
lock = threading.Lock()
init_count = 0

rolling_buffer = {
    "packet_loss": deque(maxlen=ROLLING_WINDOW_SIZE),
    "latency_jitter": deque(maxlen=ROLLING_WINDOW_SIZE),
    "dns_resolve_time": deque(maxlen=ROLLING_WINDOW_SIZE),
    "download": deque(maxlen=ROLLING_WINDOW_SIZE),
    "upload": deque(maxlen=ROLLING_WINDOW_SIZE),
    "hop_count": deque(maxlen=ROLLING_WINDOW_SIZE),
    "per_hop_rtt": deque(maxlen=ROLLING_WINDOW_SIZE),
}

# === Feature Functions ===
def analyze_ping(target="8.8.8.8", count=3):
    try:
        result = subprocess.run(["ping", "-n", str(count), target], capture_output=True, text=True, check=True)
        output = result.stdout
        packet_loss_match = re.search(r'(\d+(?:\.\d+)?)% loss', output)
        packet_loss = float(packet_loss_match.group(1)) if packet_loss_match else 0.0
        rtts = [float(rtt) for rtt in re.findall(r'time=(\d+(?:\.\d+)?)', output)]
        jitter = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
        return {"packet_loss": packet_loss, "latency_jitter": jitter}
    except:
        return {"packet_loss": 100.0, "latency_jitter": 0.0}

def dns_resolve_time(domains=['google.com', 'cloudflare.com', 'openai.com']):
    times = []
    for domain in domains:
        start = time.time()
        try:
            socket.gethostbyname(domain)
        except:
            continue
        end = time.time()
        times.append((end - start) * 1000)
    return round(statistics.mean(times), 2) if times else 1000.0

def congestion_test():
    st = speedtest.Speedtest()
    st.get_best_server()
    download = st.download() / 1_000_000
    upload = st.upload() / 1_000_000
    congestion = {
        'download': round(download, 3),
        'upload': round(upload, 3)
        #'download_vs_baseline': round((download / baseline_download) * 100, 2),
        #'upload_vs_baseline': round((upload / baseline_upload) * 100, 2),
    }
    return congestion

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
    
# ===== Helper/Calculation Functions =====
def safe_json_load(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_rolling_buffer():
    with open(ROLLING_BUFFER_FILE, 'wb') as f:
        pickle.dump(rolling_buffer, f)

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
        except:
            init_count = 0

# === Max Baseline Functions (Updated) ===
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
        if "packet_loss_ratio" in max_values:
            max_values["packet_loss_ratio"] *= 2
        if "latency_jitter_ratio" in max_values:
            max_values["latency_jitter_ratio"] *= 2
        if "dns_resolve_time_ratio" in max_values:
            max_values["dns_resolve_time_ratio"] *= 2
        #if "download_ratio" in max_values:
            #max_values["download_ratio"] *= 2
        #if "upload_ratio" in max_values:
            #max_values["upload_ratio"] *= 2
        if "hop_count_ratio" in max_values:
            max_values["hop_count_ratio"] *= 2
        if "per_hop_rtt_ratio" in max_values:
            max_values["per_hop_rtt_ratio"] *= 2

    full_max[DOMAIN_KEY] = max_values
    with open(MAX_BASELINE_FILE, 'w') as f:
        json.dump(full_max, f, indent=2)
        
def get_max_baseline():
    full_max = safe_json_load(MAX_BASELINE_FILE)
    return full_max.get(DOMAIN_KEY, {})

def save_baseline():
    max_baseline = get_max_baseline()
    try:
        max_baseline[DOMAIN_KEY]
    except KeyError:
        max_baseline[DOMAIN_KEY] = {
            "packet_loss_ratio": 1.0,
            "latency_jitter_ratio": 1.0,
            "dns_resolve_time_ratio": 1.0,
            #"download_ratio": 1.0,
            #"upload_ratio": 1.0,
            "hop_count_ratio": 1.0,
            "per_hop_rtt_ratio": 1.0
        }
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
    with open(MAX_BASELINE_FILE, 'w') as f:
        json.dump(max_baseline, f, indent=2)

def ensure_baseline_files_exist():
    if not os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, 'w') as f:
            json.dump({DOMAIN_KEY: {
                "packet_loss_ratio": 0,
                "latency_jitter_ratio": 0,
                "dns_resolve_time_ratio": 0,
                "hop_count_ratio": 0,
                "per_hop_rtt_ratio": 0
            }}, f, indent=2)

    if not os.path.exists(MAX_BASELINE_FILE):
        with open(MAX_BASELINE_FILE, 'w') as f:
            json.dump({DOMAIN_KEY: {
                "packet_loss_ratio": 0,
                "latency_jitter_ratio": 0,
                "dns_resolve_time_ratio": 0,
                "hop_count_ratio": 0,
                "per_hop_rtt_ratio": 0
            }}, f, indent=2)

def init_csv():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                #"packet_loss_ratio", "latency_jitter_ratio", "dns_resolve_time_ratio",
                #"download_ratio", "upload_ratio", "hop_count_ratio", "per_hop_rtt_ratio"
                
                "packet_loss_ratio", "latency_jitter_ratio", "dns_resolve_time_ratio",
                "hop_count_ratio", "per_hop_rtt_ratio"
            ])

def collect_metrics():
    global init_count
    while True:
        if is_logging:
            with lock:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                ping = analyze_ping()
                dns_time = dns_resolve_time()
                #speed = congestion_test()
                trace = traceroute_analysis()

                values = {
                    "packet_loss": ping["packet_loss"],
                    "latency_jitter": ping["latency_jitter"],
                    "dns_resolve_time": dns_time,
                    #"download": speed["download"],
                    #"upload": speed["upload"],
                    "hop_count": trace["hop_count"],
                    "per_hop_rtt": trace["per_hop_rtt"]
                }

                for k in values:
                    rolling_buffer[k].append(values[k])

                if init_count < MAX_BASELINE_INIT_COUNT:
                    update_max_baseline()
                    init_count += 1
                    with open(INIT_COUNT_FILE, 'w') as f:
                        f.write(str(init_count))

                save_rolling_buffer()
                save_baseline()
                
                baseline = safe_json_load(BASELINE_FILE).get(DOMAIN_KEY, {})
                ratios = {
                    f"{k}_ratio": (values[k] / baseline[k]) if baseline.get(k) else 0.0
                    for k in values
                }

                row = [timestamp] + [ratios[k] for k in [
                    #"packet_loss_ratio", "latency_jitter_ratio", "dns_resolve_time_ratio",
                    #"download_ratio", "upload_ratio", "hop_count_ratio", "per_hop_rtt_ratio"
                    
                    "packet_loss_ratio", "latency_jitter_ratio", "dns_resolve_time_ratio",
                    "hop_count_ratio", "per_hop_rtt_ratio"
                ]] + [current_label]

                with open(LOG_FILE, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(row)

        time.sleep(LOG_INTERVAL)

def user_input():
    global is_logging, current_label
    print("Commands: start | stop | label <name> | exit")
    while True:
        cmd = input(">> ").strip()
        if cmd == "start":
            is_logging = True
            print("[✓] Logging started.")
        elif cmd == "stop":
            is_logging = False
            print("[!] Logging stopped.")
        elif cmd.startswith("label"):
            _, label = cmd.split(" ", 1)
            current_label = label.strip()
            print(f"[i] Label set to: {current_label}")
        elif cmd == "exit":
            print("[x] Exiting.")
            break
        else:
            print("[x] Unknown command.")

if __name__ == "__main__":
    init_csv()
    load_init_count()
    load_rolling_buffer()
    ensure_baseline_files_exist()
    threading.Thread(target=collect_metrics, daemon=True).start()
    user_input()

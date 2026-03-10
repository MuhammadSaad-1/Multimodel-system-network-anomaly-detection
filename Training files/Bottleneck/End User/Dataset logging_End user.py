# end_user_bottleneck_logger.py
import csv
import time
import threading
import os
import json
import pickle
from datetime import datetime
import psutil
import socket
import pyshark
import asyncio
from collections import deque

# === Constants ===
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILE = os.path.join(BASE_DIR, "End User", "End-user-bottleneck-dataset.csv")
BASELINE_FILE = os.path.join(BASE_DIR, "baseline_metrics.json")
MAX_BASELINE_FILE = os.path.join(BASE_DIR, "max_baseline_metrics.json")
INIT_COUNT_FILE = os.path.join(BASE_DIR, "init_count.txt")
ROLLING_BUFFER_FILE = os.path.join(BASE_DIR, "rolling_buffer.pkl")
DOMAIN_KEY = "end_user_device"
LOG_INTERVAL = 3
SAMPLE_DURATION = 5
ROLLING_WINDOW_SIZE = 50
MAX_BASELINE_INIT_COUNT = 15

# === Globals ===
is_logging = False
current_label = "Normal"
lock = threading.Lock()
init_count = 0

rolling_buffer = {
    "avg_total_cpu": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_per_core": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_ram_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_swap_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_av_cpu": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_network_proc_cpu": deque(maxlen=ROLLING_WINDOW_SIZE),
    "avg_tcp_retrans_rate": deque(maxlen=ROLLING_WINDOW_SIZE)
}

# === Utility ===
def load_init_count():
    global init_count
    if os.path.exists(INIT_COUNT_FILE):
        try:
            with open(INIT_COUNT_FILE, 'r') as f:
                init_count = int(f.read().strip())
        except:
            init_count = 0


def safe_json_load(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

# === Monitoring Functions ===
def get_top_network_interface():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]

    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                return iface_name
    return None

def get_cpu_usage():
    total_cpu = psutil.cpu_percent(interval=None)
    per_core = psutil.cpu_percent(interval=None, percpu=True)
    return {"total_cpu": total_cpu, "per_core": per_core}

def get_memory_usage():
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {"ram_percent": mem.percent, "swap_percent": swap.percent}

def get_tcp_retransmissions(interface):
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
        capture = pyshark.LiveCapture(interface=interface, bpf_filter="tcp")
        capture.sniff(timeout=SAMPLE_DURATION)
        packets = [pkt for pkt in capture._packets]
        capture.close()

        total_tcp = 0
        retransmissions = 0
        for pkt in packets:
            try:
                if 'TCP' in pkt:
                    total_tcp += 1
                    if hasattr(pkt.tcp, 'analysis_retransmission'):
                        retransmissions += 1
            except AttributeError:
                continue

        retrans_rate = (retransmissions / total_tcp * 100) if total_tcp > 0 else 0
        return round(retrans_rate, 2)

    except Exception as e:
        print(f"[x] PyShark error in TCP retransmissions: {e}")
        return 0.0

def get_top_network_process_by_cpu():
    process_cpu_map = {}
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc.cpu_percent(interval=None)
        except:
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
    global init_count
    full_max = safe_json_load(MAX_BASELINE_FILE)
    max_values = full_max.get(DOMAIN_KEY, {})

    for k in rolling_buffer:
        avg = sum(rolling_buffer[k]) / len(rolling_buffer[k]) if rolling_buffer[k] else 0
        if k not in max_values or avg > max_values[k]:
            max_values[k] = avg

    # Apply scaling only during initialization phase
    if init_count == MAX_BASELINE_INIT_COUNT - 1:
        if "avg_total_cpu" in max_values:
            max_values["avg_total_cpu"] *= 2.5
        if "avg_per_core" in max_values:
            max_values["avg_per_core"] *= 2.5
        if "avg_ram_percent" in max_values:
            max_values["avg_ram_percent"] *= 1.5
        if "avg_swap_percent" in max_values:
            max_values["avg_swap_percent"] *= 1.5
        if "avg_av_cpu" in max_values:
            max_values["avg_av_cpu"] *= 10
        if "avg_network_proc_cpu" in max_values:
            max_values["avg_network_proc_cpu"] *= 2.5
        if "avg_tcp_retrans_rate" in max_values:
            max_values["avg_tcp_retrans_rate"] *= 1.5

    full_max[DOMAIN_KEY] = max_values
    with open(MAX_BASELINE_FILE, 'w') as f:
        json.dump(full_max, f, indent=2)

def get_max_baseline():
    full_max = safe_json_load(MAX_BASELINE_FILE)
    return full_max.get(DOMAIN_KEY, {})

# === Data Handling ===
def init_csv():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                "timestamp", "cpu_ratio", "core_ratio", "ram_ratio",
                "swap_ratio", "av_cpu_ratio", "net_proc_cpu_ratio",
                "tcp_retrans_ratio", "label"
            ])

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

def collect_metrics():
    global current_label, init_count
    interface = get_top_network_interface()

    while True:
        if is_logging:
            with lock:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                cpu_stats = get_cpu_usage()
                mem_stats = get_memory_usage()
                av_cpu = get_top_antivirus_by_cpu()
                net_cpu = get_top_network_process_by_cpu()
                tcp_retrans = get_tcp_retransmissions(interface)

                values = {
                    "avg_total_cpu": cpu_stats["total_cpu"],
                    "avg_per_core": sum(cpu_stats["per_core"]) / len(cpu_stats["per_core"]),
                    "avg_ram_percent": mem_stats["ram_percent"],
                    "avg_swap_percent": mem_stats["swap_percent"],
                    "avg_av_cpu": av_cpu,
                    "avg_network_proc_cpu": net_cpu,
                    "avg_tcp_retrans_rate": tcp_retrans
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

                baseline_values = safe_json_load(BASELINE_FILE).get(DOMAIN_KEY, {})

                ratios = {
                    k.replace("avg_", "") + "_ratio": (values[k] / baseline_values[k]) if baseline_values.get(k) else 0
                    for k in values
                }

                row = [timestamp] + [ratios[k] for k in [
                    "total_cpu_ratio", "per_core_ratio", "ram_percent_ratio",
                    "swap_percent_ratio", "av_cpu_ratio", "network_proc_cpu_ratio",
                    "tcp_retrans_rate_ratio"]] + [current_label]

                with open(LOG_FILE, mode='a', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(row)

        time.sleep(LOG_INTERVAL)

def user_input():
    global is_logging, current_label
    print("Commands: \n'start' to begin logging\n'stop' to pause\n'label <label_name>' to set new bottleneck label\n'exit' to stop program")
    while True:
        cmd = input("Enter command: ").strip()
        if cmd == "start":
            is_logging = True
            print("[✓] Logging started")
        elif cmd == "stop":
            is_logging = False
            print("[!] Logging stopped")
        elif cmd.startswith("label"):
            parts = cmd.split(" ", 1)
            if len(parts) == 2:
                current_label = parts[1].strip()
                print(f"[i] Label set to '{current_label}'")
            else:
                print("[x] Usage: label <label_name>")
        elif cmd == "exit":
            print("[!] Exiting logging...")
            break
        else:
            print("[x] Invalid command")

if __name__ == "__main__":
    init_csv()
    load_rolling_buffer()
    load_init_count()
    threading.Thread(target=collect_metrics, daemon=True).start()
    user_input()
    
# === End of File ===
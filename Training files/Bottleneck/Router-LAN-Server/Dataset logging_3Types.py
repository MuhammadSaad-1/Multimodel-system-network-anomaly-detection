import csv
import time
import threading
import os
import json
import pickle
import subprocess
import re
import time
import socket
import psutil
from datetime import datetime
from collections import deque

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILE = os.path.join(BASE_DIR, "Router-LAN-Server", "3Types-bottleneck-dataset.csv")
BASELINE_FILE = os.path.join(BASE_DIR, "baseline_metrics.json")
MAX_BASELINE_FILE = os.path.join(BASE_DIR, "max_baseline_metrics.json")
INIT_COUNT_FILE = os.path.join(BASE_DIR, "init_count.txt")
ROLLING_BUFFER_FILE = os.path.join(BASE_DIR, "rolling_buffer3Types.pkl")
DOMAIN_KEY = "Router-LAN-Server"
LOG_INTERVAL = 3  # In seconds. Time between consecutive metric collection cycles.
ROLLING_WINDOW_SIZE = 50
MAX_BASELINE_INIT_COUNT = 15

# === Globals ===
is_logging = False
current_label = "Normal"
lock = threading.Lock()
init_count = 0
default_interface = "Wi-Fi"  # Default interface to use if not found on Windows

METRIC_KEYS = [
    "signal_strength_percent",
    "channel_congestion_percent",
    "gateway_ping_ms",
    "gateway_packet_loss_percent",
    "crc_error_rate"
]

rolling_buffer = {
    "signal_strength_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "channel_congestion_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "gateway_ping_ms": deque(maxlen=ROLLING_WINDOW_SIZE),
    "gateway_packet_loss_percent": deque(maxlen=ROLLING_WINDOW_SIZE),
    "crc_error_rate": deque(maxlen=ROLLING_WINDOW_SIZE)
}

# === Monitor Functions ===
def get_top_network_interface():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]

    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                return iface_name
    return default_interface

#Windows:
def gateway_ip():
    try:
        result = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True)
        match = re.search(r"Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)", result.stdout)
        return match.group(1) if match else None
    except subprocess.CalledProcessError:
        return None

'''
#linux:
import platform

def gateway_ip():
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True)
            match = re.search(r"Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)", result.stdout)
            return match.group(1) if match else None
        else:
            # Linux / macOS
            result = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True)
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
            return match.group(1) if match else None
    except subprocess.CalledProcessError as e:
        print(f"[x] Error getting gateway IP: {e}")
        return None
'''

#For Windows:
def get_wifi_signal_strength():
    try:
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, check=True)
        output = result.stdout
        signal = re.search(r"^\s*Signal\s*:\s*(\d+)\s*%", output, re.MULTILINE)
        profile = re.search(r"^\s*Profile\s*:\s*(.+)$", output, re.MULTILINE)
        return int(signal.group(1)) if signal else None, profile.group(1).strip() if profile else None
    except subprocess.CalledProcessError:
        return None, None

'''
#linux:
import subprocess
import re

def get_wifi_signal_strength():
    try:
        result = subprocess.run(
            ["nmcli", "-f", "IN-USE,SSID,SIGNAL", "device", "wifi"],
            capture_output=True, text=True, check=True
        )
        output = result.stdout.strip().splitlines()

        print("[DEBUG] nmcli output:\n", "\n".join(output))  # Debug line

        for line in output[1:]:  # Skip header
            if line.startswith("*"):
                parts = re.split(r'\s{2,}', line.strip())
                if len(parts) >= 3:
                    ssid = parts[1]
                    signal = int(parts[2])
                    return signal, ssid
        return -100, "Unknown"
    except Exception as e:
        print(f"[x] Error fetching Wi-Fi signal: {e}")
        return -100, "Unknown"
'''

#Windows:
def get_channel_utilization(ssid_name):
    try:
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, check=True)
        blocks = re.split(r"SSID \d+ :", result.stdout)
        for block in blocks:
            if ssid_name and ssid_name in block:
                match = re.search(r"Channel Utilization:\s+(\d+)\s+\((\d+)\s*%\)", block)
                return int(match.group(2)) if match else None
        return None
    except subprocess.CalledProcessError:
        return None

'''
#Linux
def get_channel_utilization(ssid_name):
    try:
        # List available Wi-Fi networks with BSSID, SSID, frequency, and signal
        result = subprocess.run(["nmcli", "-f", "SSID,CHAN,SIGNAL", "device", "wifi", "list"],
            capture_output=True, text=True, check=True)
        output = result.stdout.strip().splitlines()

        # Skip header
        for line in output[1:]:
            parts = re.split(r'\s{2,}', line.strip())
            if len(parts) >= 3:
                ssid, channel, signal = parts[0], parts[1], parts[2]
                if ssid == ssid_name:
                    # Approximate "channel utilization" based on signal strength
                    # (Linux doesn't report actual channel utilization directly)
                    signal_int = int(signal)
                    estimated_utilization = min(100, max(0, 100 - signal_int))  # inverse of signal strength
                    return estimated_utilization
        return None
    except Exception as e:
        print(f"[x] Error in get_channel_utilization(): {e}")
        return None
'''

#Windows:
import subprocess
import platform

def is_wireless():
    if platform.system().lower() != "windows":
        return False  # Use Linux-specific logic if needed

    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, check=True
        )
        output = result.stdout.lower()
        if "state" in output and "connected" in output:
            return True
    except Exception as e:
        print(f"[DEBUG] is_wireless() error: {e}")
    
    return False

'''
#Linux:
def is_wireless():
    try:
        result = subprocess.run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device"], capture_output=True, text=True)
        for line in result.stdout.strip().splitlines():
            if ":wifi" in line:
                return True
        return False
    except Exception:
        return False
'''
'''
#Linux:
def get_ping_latency_to_gateway():
    try:
        gateway_ = gateway_ip()
        if not gateway_:
            return None
        result = subprocess.run(
            ["ping", "-c", "1", gateway_],
            capture_output=True, text=True, check=False
        )
        match = re.search(r"rtt .* = [\d.]+/([\d.]+)", result.stdout)
        return float(match.group(1)) if match else 0.0
    except Exception as e:
        print(f"[x] Error measuring gateway latency: {e}")
        return 0.0
'''
#Windows:
def get_ping_latency_to_gateway():
    try:
        gateway_ = gateway_ip()
        if not gateway_:
            return None
        result = subprocess.run(
            ["ping", "-n", "1", gateway_],
            capture_output=True, text=True, check=False
        )
        # Extract average latency
        match = re.search(r"Average = (\d+)\s*ms", result.stdout)
        return float(match.group(1)) if match else 0.0
    except Exception as e:
        print(f"[x] Error measuring gateway latency: {e}")
        return 0.0


'''
#linux
import re
import subprocess

def get_gateway_packet_loss(ping_count=3):
    try:
        gateway = gateway_ip()  # Make sure this returns the correct IP string
        if not gateway:
            return None

        result = subprocess.run(
            ["ping", gateway, "-c", str(ping_count)],
            capture_output=True, text=True
        )

        # Extract the % packet loss from the ping output
        match = re.search(r"(\d+\.?\d*)%\s*packet loss", result.stdout)
        if match:
            return float(match.group(1))  # Return as percentage (e.g., 33.3)
        else:
            return 100.0  # Assume full loss if not found

    except Exception as e:
        print(f"[x] Error getting packet loss: {e}")
        return 100.0
'''

#Windows:
import re
import subprocess

def get_gateway_packet_loss(count=10, timeout=1000):
    gateway_ip1 = gateway_ip()
    if not gateway_ip1:
        print("Could not find default gateway.")
        return None

    cmd = ['ping', gateway_ip1, '-n', str(count), '-w', str(timeout)]
    result = subprocess.run(cmd, capture_output=True, text=True)

    # Look for packet loss line
    match = re.search(r'(\d+)%\s*loss', result.stdout)
    if match:
        return int(match.group(1))  # Packet loss percentage
    else:
        print("Could not parse packet loss.")
        return None


def get_crc_error_rate():
    try:
        powershell_cmd = "Get-Counter -Counter '\\Network Interface(*)\\Packets Received Errors'"
        output = subprocess.check_output(["powershell", "-Command", powershell_cmd], text=True)
        values = [float(line.strip()) for line in output.splitlines() if line.strip().replace('.', '', 1).isdigit()]
        return round(sum(values), 3) if values else -1.0
    except Exception:
        return -1.0

'''
#linux:
def get_crc_error_rate(interface=get_top_network_interface()):
    try:
        path = f"/sys/class/net/{interface}/statistics/rx_crc_errors"
        if os.path.exists(path):
            with open(path, "r") as f:
                errors = int(f.read().strip())
                return errors
        else:
            print(f"[x] CRC error stat file not found for interface {interface}")
            return -1.0
    except Exception as e:
        print(f"[x] Error reading CRC error rate: {e}")
        return -1.0
'''

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
    else:
        # Create and save initial empty rolling buffer
        for k in rolling_buffer:
            rolling_buffer[k] = deque(maxlen=ROLLING_WINDOW_SIZE)
        with open(ROLLING_BUFFER_FILE, 'wb') as f:
            pickle.dump({k: list(v) for k, v in rolling_buffer.items()}, f)

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
        if "signal_strength_percent" in max_values:
            max_values["signal_strength_percent"] = 40
        if "channel_congestion_percent" in max_values:
            max_values["channel_congestion_percent"] = 70
        if "gateway_ping_ms" in max_values:
            max_values["gateway_ping_ms"] = 150
        if "gateway_packet_loss_percent" in max_values:
            max_values["gateway_packet_loss_percent"] = 8
        if "crc_error_rate" in max_values:
            max_values["crc_error_rate"] = 10

    full_max[DOMAIN_KEY] = max_values
    with open(MAX_BASELINE_FILE, 'w') as f:
        json.dump(full_max, f, indent=2)
        
def get_max_baseline():
    full_max = safe_json_load(MAX_BASELINE_FILE)
    return full_max.get(DOMAIN_KEY, {})

def save_baseline():
    max_baseline = get_max_baseline()
    '''
    try:
        max_baseline[DOMAIN_KEY]
    except KeyError:
        max_baseline[DOMAIN_KEY] = {
            "signal_strength_percent": 1.0,
            "channel_congestion_percent": 1.0,
            "gateway_ping_ms": 1.0,
            "gateway_packet_loss_percent": 1.0,
            "crc_error_rate": 1.0
        }
    '''
    
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

def init_csv():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "signal_strength_percent", "channel_congestion_percent", "gateway_ping_ms"
                "gateway_packet_loss_percent", "crc_error_rate", "label"
            ])

#Main Loop functions
def collect_metrics():
    global init_count
    while True:
        if is_logging:
            with lock:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(is_wireless())
                if is_wireless():
                    signal_strength, ssid = get_wifi_signal_strength()
                    channel_util = get_channel_utilization(ssid)
                else:
                    signal_strength = -1
                    channel_util = -1
                ping_latency = get_ping_latency_to_gateway()
                packet_loss = get_gateway_packet_loss(3)
                crc_error = get_crc_error_rate()

                values = {
                    "signal_strength_percent": signal_strength if signal_strength is not None else 0,
                    "channel_congestion_percent": channel_util if channel_util is not None else 0,
                    "gateway_ping_ms": ping_latency if ping_latency is not None else 0,
                    "gateway_packet_loss_percent": packet_loss if packet_loss is not None else 0,
                    "crc_error_rate": crc_error if crc_error is not None else 0,
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
                    f"{k}": (values[k] / baseline[k]) if baseline.get(k) else 0.0
                    for k in values
                }

                row = [timestamp] + [ratios[k] for k in [
                    "signal_strength_percent", "channel_congestion_percent",
                    "gateway_ping_ms", "gateway_packet_loss_percent",
                    "crc_error_rate"
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
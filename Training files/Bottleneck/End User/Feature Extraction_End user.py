from datetime import datetime
import psutil
import socket
import os 
import subprocess 
import time

SAMPLE_DURATION = 5
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TSHARK_PATH = os.path.join(BASE_DIR, 'Wireshark', 'tshark.exe')

# ===== monitoring functions ======
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

def get_tcp_retransmissions(interface, duration=3):
    """
    Calculates TCP retransmission rate using tshark for a specified duration.

    Parameters:
    - interface: str, name of the network interface (e.g., 'Wi-Fi', 'Ethernet')
    - duration: int, time in seconds to capture packets

    Returns:
    - float: TCP retransmission rate as a percentage
    """
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
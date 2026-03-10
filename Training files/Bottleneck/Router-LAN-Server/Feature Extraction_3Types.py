#Contains Feature extraction code for Router, LAN and Server related variables
'''
import subprocess
import re
import requests
import time
import socket
from urllib.parse import urlparse
'''
'''
# === CONFIGURATION ===
TEST_URL = "https://www.google.com"  # Change as needed
TEST_PORTS = [80, 443]               # Ports to test TCP handshakes
TCP_TEST_HOST = "google.com"        # Used for TCP handshake tests
NUM_REQUESTS = 10                    # Used for HTTP 5xx rate calculation
'''

'''
#Router variables
def get_wifi_signal_strength():
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout
        signal = re.search(r"^\s*Signal\s*:\s*(\d+)\s*%", output, re.MULTILINE)
        profile = re.search(r"^\s*Profile\s*:\s*(.+)$", output, re.MULTILINE)
        profile_name = profile.group(1).strip() if profile else None
        if signal:
            signal_percent = int(signal.group(1))
            return signal_percent, profile_name
        else:
            return None
    except subprocess.CalledProcessError as e:
        print("Error executing netsh:", e)
        return None

def get_channel_utilization(ssid_name):
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            check=True
        )
        output = result.stdout

        # Find all SSID blocks
        blocks = re.split(r"SSID \d+ :", output)
        for block in blocks:
            if ssid_name in block:
                # Stop at first SSID match and search for channel utilization
                match = re.search(r"Channel Utilization:\s+(\d+)\s+\((\d+)\s*%\)", block)
                if match:
                    utilization_percent = int(match.group(2))
                    return utilization_percent
                else:
                    print("Channel utilization not reported for this SSID.")
                    return None

        print("SSID not found.")
        return None

    except subprocess.CalledProcessError as e:
        print("Failed to run netsh:", e)
        return None

def get_wifi_interferance():    #wrapper function for two variables
    signal_strngth, profile = get_wifi_signal_strength()
    print(signal_strngth, profile)

    util = get_channel_utilization(profile)
    print(util)

def gateway_ip():     #helper function
    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            check=True
        )
        match = re.search(r"Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)", result.stdout)
        if not match:
            print("Default gateway not found.")
            return None

        return match.group(1)
    except subprocess.CalledProcessError as e:
        print("Error:", e)
        return None

def get_ping_latency_to_gateway():
    try:
        gateway_ = gateway_ip()
        ping_result = subprocess.run(
            ["ping", gateway_, "-n", "1"],
            capture_output=True,
            text=True,
            check=True
        )

        ping_output = ping_result.stdout
        latency_match = re.search(r"Average = (\d+)ms", ping_output)
        if latency_match:
            latency_ms = int(latency_match.group(1))
            return latency_ms
        else:
            return None

    except subprocess.CalledProcessError as e:
        print("Error:", e)
        return None

def get_gateway_packet_loss(ping_count):
    try:
        gateway_ = gateway_ip()
        ping_result = subprocess.run(
            ["ping", gateway_, "-n", str(ping_count)],
            capture_output=True,
            text=True,
            check=True
        )

        loss_match = re.search(r"(\d+)% loss", ping_result.stdout)
        if loss_match:
            loss_percent = int(loss_match.group(1))
            return loss_percent
        else:
            return None

    except subprocess.CalledProcessError as e:
        print("Ping failed:", e)
        return None
    
#LAN variables
# === 1. CRC ERROR RATE ===
def get_crc_error_rate():
    try:
        powershell_cmd = "Get-Counter -Counter '\\Network Interface(*)\\Packets Received Errors'"
        output = subprocess.check_output(["powershell", "-Command", powershell_cmd], text=True)
        #print(output)
        lines = output.splitlines()
        values = [float(line.strip()) for line in lines if line.strip().replace('.', '', 1).isdigit()]
        #print(values)
        if values:
            avg_crc_errors = sum(values)
            return round(avg_crc_errors, 3)
        
    except Exception as e:
        print(f"[CRC Error Rate] Failed: {e}")
    return -1.0

# Not Real time but to check server issues
'''
'''
# === 2. TIME-TO-FIRST-BYTE (TTFB) ===
def measure_ttfb(url):
    try:
        start = time.perf_counter()
        response = requests.get(url, stream=True, timeout=5)
        first_byte_time = time.perf_counter()
        if response.status_code:
            ttfb = first_byte_time - start
            return round(ttfb, 3)
    except Exception as e:
        print(f"[TTFB] Failed: {e}")
    return -1.0

# === 3. HTTP 5XX ERROR RATE ===
def get_http_5xx_error_rate(url, num_requests=10):
    error_count = 0
    for _ in range(num_requests):
        try:
            resp = requests.get(url, timeout=5)
            print("HTTP req sent")
            if 500 <= resp.status_code < 600:
                error_count += 1
        except Exception as e:
            print(f"[5xx Rate] Request failed: {e}")
    rate = error_count / num_requests
    return round(rate, 3)

# === 4. TCP HANDSHAKE SUCCESS RATE ===
def tcp_handshake_success_rate(host, ports):
    success = 0
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=3):
                success += 1
                print("TCP")
        except Exception:
            pass
    rate = success / len(ports)
    return round(rate, 3)
'''
'''
# === MAIN ===
if __name__ == "__main__":
    print("[*] Extracting network features...\n")
    
    latency = get_ping_latency_to_gateway()
    packet_loss = get_gateway_packet_loss(3)
    crc_rate = get_crc_error_rate()
    #ttfb = measure_ttfb(TEST_URL)
    #http_5xx = get_http_5xx_error_rate(TEST_URL, NUM_REQUESTS)
    #tcp_rate = tcp_handshake_success_rate(TCP_TEST_HOST, TEST_PORTS)

    get_wifi_interferance()
    print(f"latency to gateway      : {latency} ms")
    print(f"packet loss             : {packet_loss} %")
    print(f"CRC Error Amount        : {crc_rate} errors")
    #print(f"Time To First Byte     : {ttfb} seconds")
    #print(f"HTTP 5xx Error Rate    : {http_5xx} errors/requests")
    #print(f"TCP Handshake Success  : {tcp_rate} successful ports/num. ports")
'''
import subprocess
import re
import requests
import time
import socket
from urllib.parse import urlparse

# === CONFIGURATION ===
REPEAT_COUNT = 3

# Helper functions
def gateway_ip():
    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            check=True
        )
        match = re.search(r"Default Gateway[^\d]*(\d+\.\d+\.\d+\.\d+)", result.stdout)
        return match.group(1) if match else None
    except subprocess.CalledProcessError:
        return None

# === FEATURE EXTRACTION FUNCTIONS ===

def get_wifi_signal_strength():
    try:
        result = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                                capture_output=True, text=True, check=True)
        output = result.stdout
        signal = re.search(r"^\s*Signal\s*:\s*(\d+)\s*%", output, re.MULTILINE)
        profile = re.search(r"^\s*Profile\s*:\s*(.+)$", output, re.MULTILINE)
        profile_name = profile.group(1).strip() if profile else None
        return int(signal.group(1)) if signal else None, profile_name
    except subprocess.CalledProcessError:
        return None, None

def get_channel_utilization(ssid_name):
    try:
        result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                                capture_output=True, text=True, check=True)
        output = result.stdout
        blocks = re.split(r"SSID \d+ :", output)
        for block in blocks:
            if ssid_name and ssid_name in block:
                match = re.search(r"Channel Utilization:\s+(\d+)\s+\((\d+)\s*%\)", block)
                return int(match.group(2)) if match else None
        return None
    except subprocess.CalledProcessError:
        return None

def get_ping_latency_to_gateway():
    try:
        gateway_ = gateway_ip()
        if not gateway_:
            return None
        result = subprocess.run(["ping", gateway_, "-n", "1"],
                                capture_output=True, text=True, check=True)
        match = re.search(r"Average = (\d+)ms", result.stdout)
        return int(match.group(1)) if match else None
    except subprocess.CalledProcessError:
        return None

def get_gateway_packet_loss(ping_count):
    try:
        gateway_ = gateway_ip()
        if not gateway_:
            return None
        result = subprocess.run(["ping", gateway_, "-n", str(ping_count)],
                                capture_output=True, text=True, check=True)
        match = re.search(r"(\d+)% loss", result.stdout)
        return int(match.group(1)) if match else None
    except subprocess.CalledProcessError:
        return None

def get_crc_error_rate():
    try:
        powershell_cmd = "Get-Counter -Counter '\\Network Interface(*)\\Packets Received Errors'"
        output = subprocess.check_output(["powershell", "-Command", powershell_cmd], text=True)
        lines = output.splitlines()
        values = [float(line.strip()) for line in lines if line.strip().replace('.', '', 1).isdigit()]
        return round(sum(values), 3) if values else -1.0
    except Exception:
        return -1.0

# === MAIN LOOP ===
if __name__ == "__main__":
    signal_strengths = []
    channel_utils = []
    latencies = []
    packet_losses = []
    crc_errors = []

    ssid_name = None

    for _ in range(REPEAT_COUNT):
        signal_strength, profile = get_wifi_signal_strength()
        if profile and not ssid_name:
            ssid_name = profile

        utilization = get_channel_utilization(ssid_name) if ssid_name else None
        latency = get_ping_latency_to_gateway()
        packet_loss = get_gateway_packet_loss(3)
        crc = get_crc_error_rate()

        if signal_strength is not None:
            signal_strengths.append(signal_strength)
        if utilization is not None:
            channel_utils.append(utilization)
        if latency is not None:
            latencies.append(latency)
        if packet_loss is not None:
            packet_losses.append(packet_loss)
        if crc != -1.0:
            crc_errors.append(crc)

        time.sleep(1)  # Small delay between repetitions

    # Final Averages
    def avg(values): return round(sum(values) / len(values), 2) if values else None

    print("\n=== AVERAGED NETWORK VALUES ===")
    print(f"Avg Signal Strength     : {avg(signal_strengths)}%")
    print(f"Avg Channel Utilization : {avg(channel_utils)}%")
    print(f"Avg Ping Latency        : {avg(latencies)} ms")
    print(f"Avg Packet Loss         : {avg(packet_losses)}%")
    print(f"Avg CRC Error Rate      : {avg(crc_errors)} errors/sec")
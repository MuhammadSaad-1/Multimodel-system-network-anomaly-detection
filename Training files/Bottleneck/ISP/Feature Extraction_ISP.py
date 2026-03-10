import subprocess
import re
import statistics
import time
import socket
import speedtest
from scapy.all import IP, ICMP, sr1

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
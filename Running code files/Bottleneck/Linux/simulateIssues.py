import subprocess
import os
import re

INTERFACE = "ens33"

# Clear all previous simulations
def clear_all_simulations():
    print("Clearing all existing network simulations...")
    subprocess.call(["sudo", "tc", "qdisc", "del", "dev", INTERFACE, "root"], stderr=subprocess.DEVNULL)
    subprocess.call(["sudo", "iptables", "-F"])
    subprocess.call(["sudo", "iptables", "-t", "mangle", "-F"])


# Simulate Signal Strength by adding packet loss
def simulate_signal_strength():
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "loss", "30%"])
    print("Simulating weak signal strength (30% packet loss)")

# Simulate Channel Utilization using delay + jitter
def simulate_channel_utilization():
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "delay", "50ms", "10ms"])
    print("Simulating high channel utilization (50ms delay with jitter)")

# Simulate Ping Latency to Gateway
def simulate_ping_latency_gateway():
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "delay", "1000ms"])
    print("Simulating high latency to gateway (1000ms delay)")

# Simulate Packet Loss to Gateway
def simulate_packet_loss_gateway():
    # Get the default gateway IP address
    result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
    match = re.search(r"default via ([\d.]+)", result.stdout)
    if not match:
        print("Failed to detect gateway IP.")
        return
    gateway_ip = match.group(1)

    print(f"Detected gateway IP: {gateway_ip}")

    # Add root qdisc (if not already present)
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "handle", "1:", "prio"], stderr=subprocess.DEVNULL)

    # Add netem under class 1:3 with 50% loss
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "parent", "1:3", "handle", "30:", "netem", "loss", "50%"], stderr=subprocess.DEVNULL)

    # Add filter to match traffic to gateway IP and direct it to class 1:3
    subprocess.run([
        "sudo", "tc", "filter", "add", "dev", INTERFACE, "protocol", "ip", "parent", "1:",
        "prio", "3", "u32", "match", "ip", "dst", gateway_ip, "flowid", "1:3"
    ], stderr=subprocess.DEVNULL)

    print("Simulating 50% packet loss to gateway")

# Simulate CRC Error Rate by packet corruption
def simulate_crc_errors():
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "corrupt", "10%"])
    print("Simulating CRC errors (10% corruption)")

# Simulate Packet Loss to 8.8.8.8
def simulate_isp_packet_loss():
    subprocess.run([
        "sudo", "iptables", "-A", "OUTPUT", "-d", "8.8.8.8", "-m", "statistic",
        "--mode", "random", "--probability", "0.8", "-j", "DROP"
    ])
    print("Simulating 80% packet loss to 8.8.8.8")

# Simulate Latency Jitter to 8.8.8.8
def simulate_latency_jitter():
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "delay", "800ms", "300ms"])
    print("Simulating latency jitter to 8.8.8.8 (100ms ±30ms)")

# Simulate DNS Resolution Delay
def simulate_dns_delay():
    subprocess.run([
        "sudo", "iptables", "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "53",
        "-j", "DROP"
    ])
    print("Simulating DNS resolution failure/delay (dropping DNS packets)")

# Simulate Traceroute Hop Latency
def simulate_traceroute_latency():
    subprocess.run(["sudo", "tc", "qdisc", "add", "dev", INTERFACE, "root", "netem", "delay", "400ms"])
    print("Simulating high hop latency (400ms delay)")

# Simulate TCP Retransmissions by random drop
def simulate_tcp_retransmissions():
    subprocess.run([
        "sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "-d", "8.8.8.8",
        "-m", "statistic", "--mode", "random", "--probability", "0.8", "-j", "DROP"
    ])
    print("Simulating TCP retransmissions (80% drop for TCP to 8.8.8.8)")

ISSUE_MAP = {
    "signal": simulate_signal_strength,
    "channel": simulate_channel_utilization,
    "gateway_latency": simulate_ping_latency_gateway,
    "gateway_loss": simulate_packet_loss_gateway,
    "crc": simulate_crc_errors,
    "isp_loss": simulate_isp_packet_loss,
    "jitter": simulate_latency_jitter,
    "dns": simulate_dns_delay,
    "traceroute": simulate_traceroute_latency,
    "tcp_retrans": simulate_tcp_retransmissions
}

def main():
    while True:
        print("\nEnter issue to simulate or 'exit' to quit:")
        print("Options: signal, channel, gateway_latency, gateway_loss, crc, isp_loss, jitter, dns, traceroute, tcp_retrans")
        issue = input(">> ").strip().lower()

        if issue == "exit":
            clear_all_simulations()
            print("Exiting and clearing simulations.")
            break
        elif issue in ISSUE_MAP:
            clear_all_simulations()
            ISSUE_MAP[issue]()
        else:
            print("Unknown issue type. Please enter a valid one.")

if __name__ == "__main__":
    main()

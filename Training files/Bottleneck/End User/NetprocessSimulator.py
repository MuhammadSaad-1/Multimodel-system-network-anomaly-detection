import socket
import threading
import time
import subprocess

TARGET_IP = "8.8.8.8"
TARGET_PORT = 80
NUM_THREADS = 5
DELAY_BETWEEN_CONNECTIONS = 0.2  # seconds

# Optional: Drop TCP packets to simulate retransmissions
def enable_packet_loss():
    subprocess.run([
        "sudo", "iptables", "-A", "OUTPUT", "-p", "tcp", "-d", TARGET_IP,
        "-m", "statistic", "--mode", "random", "--probability", "0.7", "-j", "DROP"
    ])
    print("Enabled artificial TCP packet loss (70%)")

# Remove packet loss rules
def disable_packet_loss():
    subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-p", "tcp", "-d", TARGET_IP,
                    "-m", "statistic", "--mode", "random", "--probability", "0.7", "-j", "DROP"],
                   stderr=subprocess.DEVNULL)
    print("Removed artificial TCP packet loss rules")

# TCP connection spammer
def tcp_sender():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((TARGET_IP, TARGET_PORT))
            sock.sendall(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
            time.sleep(0.1)
            sock.close()
        except Exception:
            pass
        time.sleep(DELAY_BETWEEN_CONNECTIONS)

if __name__ == "__main__":
    try:
        enable_packet_loss()

        for _ in range(NUM_THREADS):
            threading.Thread(target=tcp_sender, daemon=True).start()

        print("Simulating high TCP retransmission... Press Ctrl+C to stop.")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nExiting...")
        disable_packet_loss()
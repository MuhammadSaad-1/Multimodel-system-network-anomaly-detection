import socket
import time

HOST = '127.0.0.1'
PORT = 12345
MESSAGE = b'Test TCP packet\n'
INTERVAL = 0.5

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print(f"[+] Connected to {HOST}:{PORT}")
    return s

while True:
    try:
        if 's' not in locals() or s._closed:
            s = connect()
        s.sendall(MESSAGE)
        print("[→] Sent:", MESSAGE.decode().strip())
        time.sleep(INTERVAL)
    except (ConnectionResetError, BrokenPipeError) as e:
        print(f"[!] Connection error: {e}. Reconnecting in 2s...")
        s.close()
        time.sleep(2)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        break

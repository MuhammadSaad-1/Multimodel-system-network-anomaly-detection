import socket

HOST = '0.0.0.0'   # Listen on all interfaces
PORT = 12345

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen()
    print(f"[✓] Listening on port {PORT}...")
    conn, addr = server.accept()
    with conn:
        print(f"[i] Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"[←] Received: {data.decode().strip()}")

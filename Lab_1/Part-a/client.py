import socket, random
from datetime import datetime

servers = {
    1: ("10.61.110.44", 8001),
    2: ("10.61.110.44", 8002), 
    3: ("10.61.83.67", 8003),
    4: ("10.61.83.67", 8004),
    5: ("10.13.2.237", 8005),
    6: ("10.13.2.237", 8006),
    7: ("10.13.1.198", 8007),
    8: ("10.13.1.198", 8008),
}

log = "client.log"
counts = {i: 0 for i in range(1, 9)}

req = 1000

for _ in range(req):
    n = random.randint(4,4)
    host, port = servers[n]

    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((host,port))
    sock.sendall(b"hello")
    reply = sock.recv(1024).decode().strip()
    sock.close()
    counts[n] += 1
    with open(log,"a") as f:
        f.write(f"{datetime.now().isoformat(timespec='seconds')} chose={n} {host}:{port} reply={reply}\n")

with open(log,"a") as f:
    f.write(f"Final counts: {counts}\n")

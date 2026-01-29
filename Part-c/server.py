import socket, sys
from datetime import datetime

num = int(sys.argv[1])
port = int(sys.argv[2])
log = f"server_{num}.log"

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(("0.0.0.0",port))
s.listen(50)
print(f"server {num} listening on {port}")
    
while True:
    c, addr = s.accept()
    msg = c.recv(1024).decode().strip()

    with open(log,"a") as f:
        f.write(f"{datetime.now().isoformat(timespec='seconds')} from={addr[0]}:{addr[1]} msg={msg}\n")

    c.sendall(f"hello from server {num}".encode())
    c.close()
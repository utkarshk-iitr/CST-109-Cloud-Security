import socket, threading, time
from datetime import datetime

servers = {
    1: ("10.81.13.87", 8001),
    2: ("10.81.13.88", 8002),
    3: ("10.81.43.80", 8003),
    4: ("192.168.56.2", 8004),
    5: ("10.81.13.91", 8005),
    6: ("10.81.13.92", 8006),
    7: ("10.81.13.93", 8007),
    8: ("10.81.13.94", 8008),
}

def my_ip():
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.connect(("8.8.8.8",80))
    ip = s.getsockname()[0]
    s.close()
    return ip

port = 9000
log = "load_balancer.log"
healthy = {i: False for i in servers}
active  = {i: 0 for i in servers}

def logline(s):
    with open(log, "a") as f:
        f.write(f"{datetime.now().isoformat(timespec='seconds')} {s}\n")

def probe_one(i):
    host, port = servers[i]
    ok = False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.4)
        sock.connect((host, port))   
        sock.sendall(b"hello")
        resp = sock.recv(1024).decode()
        ok = resp.startswith("hello from server")
        sock.close()
    except:
        ok = False

    with threading.Lock():
        healthy[i] = ok

def health_loop():
    while True:
        threads = []
        for i in servers:
            t = threading.Thread(target=probe_one, args=(i,))
            t.start()                           
            threads.append(t)
        for t in threads:
            t.join()                            
        time.sleep(1)

def pick_best():
    with threading.Lock():
        candidates = [i for i in servers if healthy[i]]
        if not candidates:
            return None
        best = min(candidates, key=lambda i: active[i])
        active[best] += 1
        return best

def handle_client(c, addr):
    sid = pick_best()
    if sid is None:
        c.sendall(b"no healthy servers")
        c.close()
        return

    host, port = servers[sid]
    try:
        msg = c.recv(1024)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.sendall(msg)
        reply = s.recv(1024)
        s.close()

        c.sendall(reply)
        logline(f"client={addr[0]}:{addr[1]} -> server={sid} {host}:{port}")
    except Exception as e:
        logline(f"error server={sid} err={repr(e)}")
        try: c.sendall(b"lb error")
        except: pass
    finally:
        c.close()
        with threading.Lock():
            active[sid] = max(0, active[sid] - 1)

threading.Thread(target=health_loop, daemon=True).start()
lb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lb.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
lb.bind(("0.0.0.0",port))
lb.listen(200)

print(f"LB running on {my_ip()}:{port}")
while True:
    c, addr = lb.accept()
    threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()

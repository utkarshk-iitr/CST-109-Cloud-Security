import socket, time
from datetime import datetime

host = "10.81.13.87"
port = 9000
req = 1000
log = "client.log"

counts = {i: 0 for i in range(1, 9)}
lat = []
ok = 0
fail = 0

t0 = time.time()

for _ in range(req):
    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((host, port))
        sock.sendall(b"hello")
        reply = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        dt = time.time() - start
        lat.append(dt)
        ok += 1

        parts = reply.split()
        sid = int(parts[3])
        counts[sid] += 1

    except Exception as e:
        fail += 1
        with open(log, "a") as f:
            f.write(f"{datetime.now().isoformat(timespec='seconds')} error={repr(e)}\n")

t1 = time.time()
total = t1 - t0
rps = ok / total if total > 0 else 0.0

lat.sort()
def pct(p):
    if not lat:
        return None
    idx = int(p * (len(lat) - 1))
    return lat[idx]

with open(log, "a") as f:
    f.write(f"OK={ok} FAIL={fail} TOTAL_TIME={total:.3f}s RPS={rps:.2f}\n")
    if lat:
        f.write(f"LAT avg={sum(lat)/len(lat):.6f}s p95={pct(0.95):.6f}s p99={pct(0.99):.6f}s\n")
    f.write(f"SERVER_COUNTS={counts}\n")

print("RPS:", rps)
print("FAIL:", fail)
print("COUNTS:", counts)

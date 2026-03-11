import socket
import ssl
import json
import threading
import logging
import os
import sys
import hashlib
import time
from datetime import datetime
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

_SRC_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_DIR    = os.path.join(_SRC_DIR, 'certs')
SERVER_CERT = os.path.join(CERT_DIR, 'server.crt')
SERVER_KEY  = os.path.join(CERT_DIR, 'server.key')

LOG_FORM = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

STORAGE_SERVERS = [
    {'host': '10.81.5.163', 'port': 6001, 'id': 'storage_1'},
    {'host': '10.81.5.163', 'port': 6002, 'id': 'storage_2'},
    {'host': '10.81.32.45', 'port': 6003, 'id': 'storage_3'},
    {'host': '10.81.32.45', 'port': 6004, 'id': 'storage_4'},
]

MAX_CHUNK = 10 * 1024 * 1024
MAX_REQ_PER_IP = 100
INTEGRITY_CHECK = True

def init_log(sid):
    logging.basicConfig(
        level=logging.INFO, format=LOG_FORM,
        handlers=[
            logging.FileHandler(os.path.join(LOG_DIR, f'{sid}.log')),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(f'StorageServer-{sid}')

class SecMonitor:
    def __init__(self, sid):
        self.sid = sid
        self.req_counts = defaultdict(list)
        self.flagged_ips = set()
        self.lock = threading.Lock()

        self.threat_log = logging.getLogger(f'ThreatDetection-{sid}')
        handler = logging.FileHandler(os.path.join(LOG_DIR, f'threats_{sid}.log'))
        handler.setFormatter(logging.Formatter(LOG_FORM))
        self.threat_log.addHandler(handler)
        self.threat_log.setLevel(logging.WARNING)

    def check_rate_limit(self, cip):
        with self.lock:
            now = time.time()
            self.req_counts[cip] = [ts for ts in self.req_counts[cip] if now - ts < 60]
            if len(self.req_counts[cip]) >= MAX_REQ_PER_IP:
                self.threat_log.warning(f"Rate limit exceeded for {cip}")
                self.flagged_ips.add(cip)
                return False
            self.req_counts[cip].append(now)
            return True

    def is_flagged(self, cip):
        return cip in self.flagged_ips

class IntegrityManager:
    def __init__(self, sid):
        self.sid = sid
        self.cksums = {}
        self.cksum_file = os.path.join(LOG_DIR, f'{sid}_checksums.json')
        self.lock = threading.Lock()
        self.load()

    def load(self):
        try:
            if os.path.exists(self.cksum_file):
                with open(self.cksum_file, 'r') as f:
                    self.cksums = json.load(f)
        except Exception as e:
            logging.error(f"Error loading checksums: {e}")

    def save(self):
        try:
            with open(self.cksum_file, 'w') as f:
                json.dump(self.cksums, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving checksums: {e}")

    def calc_hash(self, data):
        return hashlib.sha256(data).hexdigest()

    def store_hash(self, fname, cksum):
        with self.lock:
            self.cksums[fname] = {'checksum': cksum,'timestamp': datetime.now().isoformat()}
            self.save()

    def verify(self, fname, data):
        if fname not in self.cksums:
            return None
        calculated = self.calc_hash(data)
        stored = self.cksums[fname]['checksum']
        return calculated == stored

    def get_hash(self, fname):
        return self.cksums.get(fname, {}).get('checksum')

class StorageServer:
    def __init__(self, host, port, sid):
        self.host = host
        self.port = port
        self.sid = sid
        self.store_dir = os.path.join(BASE_DIR, sid)
        self.log = init_log(sid)
        self.req_count = 0
        self.lock = threading.Lock()

        self.sec_mon = SecMonitor(sid)
        self.integrity = IntegrityManager(sid)

        os.makedirs(self.store_dir, exist_ok=True)

        self.audit = logging.getLogger(f'Audit-{sid}')
        ah = logging.FileHandler(os.path.join(LOG_DIR, f'audit_{sid}.log'))
        ah.setFormatter(logging.Formatter(LOG_FORM))
        self.audit.addHandler(ah)
        self.audit.setLevel(logging.INFO)

    def validate(self, req):
        fields = {'STORE_CHUNK': ['filename', 'chunk_id', 'chunk_size'],'RETRIEVE_CHUNK': ['filename', 'chunk_id']}

        op = req.get('operation')
        if op not in fields:
            return False, "Invalid operation"

        for f in fields[op]:
            if f not in req:
                return False, f"Missing required field: {f}"

        if op == 'STORE_CHUNK':
            csize = req.get('chunk_size', 0)
            if csize > MAX_CHUNK:
                return False, f"Chunk size exceeds maximum ({MAX_CHUNK} bytes)"
            if csize <= 0:
                return False, "Invalid chunk size"
        return True, "Valid"

    def handle_client(self, csock, addr):
        cip = addr[0]
        try:
            if not self.sec_mon.check_rate_limit(cip):
                self.log.warning(f"Rate limit exceeded for {cip}")
                err = {'status': 'ERROR', 'message': 'Rate limit exceeded'}
                csock.send(json.dumps(err).encode())
                return

            data = csock.recv(1024).decode()
            req = json.loads(data)
            op = req.get('operation')

            with self.lock:
                self.req_count += 1
                rn = self.req_count

            self.log.info(f"Request #{rn} from {cip}: {op}")
            self.audit.info(f"Request #{rn} | IP: {cip} | Operation: {op}")

            valid, msg = self.validate(req)
            if not valid:
                self.log.error(f"Invalid request from {cip}: {msg}")
                self.audit.warning(f"Invalid request from {cip}: {msg}")
                err = {'status': 'ERROR', 'message': msg}
                csock.send(json.dumps(err).encode())
                return

            if op == 'STORE_CHUNK':
                self.handle_store(csock, req, cip, rn)
            elif op == 'RETRIEVE_CHUNK':
                self.handle_retriever(csock, req, cip, rn)
            else:
                resp = {'status': 'ERROR', 'message': 'Unknown operation'}
                csock.send(json.dumps(resp).encode())

        except json.JSONDecodeError:
            self.log.error(f"Invalid JSON from {cip}")
            err = {'status': 'ERROR', 'message': 'Invalid request format'}
            try:
                csock.send(json.dumps(err).encode())
            except:
                pass
        except Exception as e:
            self.log.error(f"Error handling client {cip}: {e}")
            err = {'status': 'ERROR', 'message': str(e)}
            try:
                csock.send(json.dumps(err).encode())
            except:
                pass
        finally:
            csock.close()

    def handle_store(self, csock, req, cip, rn):
        fname = req['filename']
        cid = req['chunk_id']
        csize = req['chunk_size']

        csock.send(b'READY')

        cdata = b''
        remaining = csize
        while remaining > 0:
            data = csock.recv(min(remaining, 8192))
            if not data:
                break
            cdata += data
            remaining -= len(data)

        if len(cdata) != csize:
            self.log.error(f"Size mismatch: expected {csize}, got {len(cdata)}")
            resp = {'status': 'ERROR', 'message': 'Size mismatch'}
            csock.send(json.dumps(resp).encode())
            return resp

        cksum = self.integrity.calc_hash(cdata)
        cname = f"{fname}_chunk_{cid}"
        cpath = os.path.join(self.store_dir, cname)

        try:
            with open(cpath, 'wb') as f:
                f.write(cdata)

            if INTEGRITY_CHECK:
                self.integrity.store_hash(cname, cksum)

            self.log.info(f"Stored chunk {cid} of {fname} ({len(cdata)} bytes)")
            self.audit.info(f"Request #{rn} | STORE | {cname} | Size: {len(cdata)} | "f"Checksum: {cksum[:16]}... | IP: {cip}")

            resp = {'status': 'SUCCESS','message': 'Chunk stored successfully','chunk_id': cid,'checksum': cksum}
            csock.send(json.dumps(resp).encode())
            return resp

        except Exception as e:
            self.log.error(f"Error storing chunk: {e}")
            resp = {'status': 'ERROR', 'message': f'Storage error: {str(e)}'}
            csock.send(json.dumps(resp).encode())
            return resp

    def handle_retriever(self, csock, req, cip, rn):
        fname = req['filename']
        cid = req['chunk_id']

        cname = f"{fname}_chunk_{cid}"
        cpath = os.path.join(self.store_dir, cname)

        if not os.path.exists(cpath):
            self.log.error(f"Chunk {cid} of {fname} not found")
            self.audit.warning(f"Request #{rn} | RETRIEVE | {cname} | NOT FOUND | IP: {cip}")
            resp = {'status': 'ERROR', 'message': 'Chunk not found'}
            csock.send(json.dumps(resp).encode())
            return resp

        try:
            with open(cpath, 'rb') as f:
                cdata = f.read()

            csize = len(cdata)

            if INTEGRITY_CHECK:
                stored = self.integrity.get_hash(cname)
                calc = self.integrity.calc_hash(cdata)

                if stored and stored != calc:
                    self.log.critical(f"INTEGRITY VIOLATION: {cname}")
                    self.audit.critical(f"Request #{rn} | RETRIEVE | {cname} | "f"INTEGRITY VIOLATION | IP: {cip}")
                    resp = {'status': 'ERROR', 'message': 'Integrity check failed'}
                    csock.send(json.dumps(resp).encode())
                    return resp

            resp = {'status': 'SUCCESS','chunk_size': csize,'checksum': self.integrity.calc_hash(cdata)}
            csock.send(json.dumps(resp).encode())

            csock.recv(1024)

            sent = 0
            while sent < csize:
                chunk = cdata[sent:sent + 8192]
                csock.send(chunk)
                sent += len(chunk)

            self.log.info(f"Sent chunk {cid} of {fname} ({csize} bytes)")
            self.audit.info(f"Request #{rn} | RETRIEVE | {cname} | Size: {csize} | IP: {cip}")
            return resp

        except Exception as e:
            self.log.error(f"Error retrieving chunk: {e}")
            resp = {'status': 'ERROR', 'message': f'Retrieval error: {str(e)}'}
            try:
                csock.send(json.dumps(resp).encode())
            except:
                pass
            return resp

    def start(self):
        ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ssock.bind((self.host, self.port))
        ssock.listen(5)

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(SERVER_CERT, SERVER_KEY)
        ssock = ssl_ctx.wrap_socket(ssock, server_side=True)

        self.log.info(f"Storage Server '{self.sid}' started on {self.host}:{self.port} (TLS enabled)")
        self.log.info(f"Storage directory: {self.store_dir}")
        self.log.info(f"Security features: Rate limiting, Integrity checking, Audit logging")
        self.log.info(f"Max chunk size: {MAX_CHUNK / 1024 / 1024} MB")

        try:
            while True:
                csock, addr = ssock.accept()
                ct = threading.Thread(target=self.handle_client, args=(csock, addr))
                ct.daemon = True
                ct.start()
        except KeyboardInterrupt:
            self.log.info(f"Storage Server '{self.sid}' shutting down...")
            self.log.info(f"Total requests served: {self.req_count}")
        finally:
            ssock.close()

if len(sys.argv) != 2:
    print("Usage: python3 storage_server.py <server_number>")
    sys.exit(1)

snum = int(sys.argv[1])
if snum < 1 or snum > 4:
    print(f"Server number must be between 1 and 4")
    sys.exit(1)

cfg = STORAGE_SERVERS[snum - 1]
server = StorageServer(cfg['host'], cfg['port'], cfg['id'])
server.start()

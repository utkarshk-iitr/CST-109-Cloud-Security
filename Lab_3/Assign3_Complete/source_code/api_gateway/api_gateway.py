import sys
import socket
import json
import threading
import logging
import time
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

_SOURCE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SOURCE_DIR not in sys.path:
    sys.path.insert(0, _SOURCE_DIR)
from security_modules.mitigation_engine import *

GATEWAY_HOST = '127.0.0.1'
GATEWAY_PORT = 8080
APP_HOST = '127.0.0.1'
APP_PORT = 5000

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger('APIGateway')
gw_handler = logging.FileHandler(os.path.join(LOG_DIR, 'gateway.log'))
gw_handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger.addHandler(gw_handler)

auth_log = logging.getLogger('GW-Auth')
auth_hand = logging.FileHandler(os.path.join(LOG_DIR, 'auth.log'))
auth_hand.setFormatter(logging.Formatter(LOG_FORMAT))
auth_log.addHandler(auth_hand)
auth_log.setLevel(logging.INFO)

threat_log = logging.getLogger('GW-Threat')
threat_hand = logging.FileHandler(os.path.join(LOG_DIR, 'threats.log'))
threat_hand.setFormatter(logging.Formatter(LOG_FORMAT))
threat_log.addHandler(threat_hand)
threat_log.setLevel(logging.INFO)

mitg_log = logging.getLogger('GW-Mitigation')
mitg_hand = logging.FileHandler(os.path.join(LOG_DIR, 'mitigation.log'))
mitg_hand.setFormatter(logging.Formatter(LOG_FORMAT))
mitg_log.addHandler(mitg_hand)
mitg_log.setLevel(logging.INFO)

class APIGateway:
    def __init__(self):
        self.engine = MitigationEngine(logger=mitg_log)
        self.lock = threading.Lock()
        self.total_requests = 0
        self.threats_detected = 0
        self.mitg_applied = 0
        self.start_time = time.time()

    def record_auth(self, client_ip, request, response):
        operation = request.get('operation')
        if operation!='LOGIN': return

        username = request.get('username','unknown')
        status = response.get('status')

        if status=='SUCCESS':
            auth_log.info(f"AUTH SUCCESS | User: {username} | IP: {client_ip}")
            self.engine.record_auth_success(client_ip)
        else:
            auth_log.warning(f"AUTH FAILED | User: {username} | IP: {client_ip} | Reason: {response.get('message', 'unknown')}")
            locked = self.engine.record_auth_failure(client_ip)
            fails = self.engine.failed_auths[client_ip]

            if locked:
                threat_log.critical(f"THREAT: Brute-force attack detected | IP: {client_ip} | Failed attempts: {fails} | Target user: {username}")
                self.threats_detected += 1
                self.mitg_applied += 1
            elif fails >= 3:
                threat_log.warning(f"THREAT: Suspicious login activity | IP: {client_ip} | Failed attempts: {fails} | Target user: {username}")
                self.threats_detected += 1

    def fwd(self, data):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((APP_HOST, APP_PORT))
            sock.send(data)
            response = sock.recv(65536)
            sock.close()
            return response
        except Exception as e:
            logger.error(f"Application server unreachable: {e}")
            threat_log.warning(f"THREAT: Service unavailable | Application server down | Error: {e}")
            return json.dumps({'status': 'ERROR','message': 'Service unavailable. Backend server unreachable.'}).encode()

    def handle_client(self, client_socket, address):
        client_ip = address[0]
        request_time = time.time()

        try:
            with self.lock:
                self.total_requests += 1
                req_num = self.total_requests
            allowed, reason = self.engine.check_request(client_ip)
            if not allowed:
                if reason == 'IP blocked - DoS detected':
                    threat_log.critical(f"THREAT: DoS attack detected | IP: {client_ip} | Requests: {DOS_THRESHOLD}+/min | Action: IP blocked for {AUTO_BLOCK_DURATION}s")
                    self.threats_detected += 1
                    self.mitg_applied += 1
                    msg = 'Your IP has been blocked due to suspicious activity.'
                elif reason == 'Rate limit exceeded':
                    threat_log.warning(f"THREAT: Rate limit exceeded | IP: {client_ip}")
                    self.threats_detected += 1
                    self.mitg_applied += 1
                    msg = 'Rate limit exceeded. Try again later.'
                elif reason == 'Account locked':
                    logger.warning(f"[#{req_num}] Locked-out IP connection attempt: {client_ip}")
                    msg = 'Account locked. Try again later.'
                else:
                    logger.warning(f"[#{req_num}] Blocked IP connection attempt: {client_ip}")
                    msg = 'Your IP has been blocked due to suspicious activity.'
                error = {'status': 'ERROR', 'message': msg}
                client_socket.send(json.dumps(error).encode())
                return

            data = client_socket.recv(4096)
            if not data: return

            try:
                request = json.loads(data.decode())
                operation = request.get('operation', 'UNKNOWN')
            except:
                request = {}
                operation = 'UNKNOWN'

            logger.info(f"[#{req_num}] {client_ip} -> {operation}")
            response_data = self.fwd(data)

            try:
                response = json.loads(response_data.decode())
                self.record_auth(client_ip, request, response)

                if response.get('message') == 'Permission denied':
                    threat_log.warning(f"THREAT: Unauthorized access attempt (IDOR) | IP: {client_ip} | Operation: {operation}")
                    mitg_log.info(f"MITIGATION: IDOR blocked | IP: {client_ip} | Operation: {operation} | Action: Permission denied")
                    self.threats_detected += 1
                    self.mitg_applied += 1

                if response.get('message') in ('Invalid or expired token', 'Authentication required'):
                    threat_log.warning(f"THREAT: Invalid/tampered token | IP: {client_ip} | Operation: {operation}")
                    mitg_log.info(f"MITIGATION: Tampered token rejected | IP: {client_ip} | Action: Request denied")
                    self.threats_detected += 1
                    self.mitg_applied += 1
            except: pass

            elapsed = time.time() - request_time
            logger.info(f"[#{req_num}] {client_ip} <- {operation} ({elapsed:.3f}s)")
            client_socket.send(response_data)

        except Exception as e:
            logger.error(f"Error handling {client_ip}: {e}")
            try:
                error = {'status': 'ERROR', 'message': 'Gateway error'}
                client_socket.send(json.dumps(error).encode())
            except: pass
        finally:
            client_socket.close()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((GATEWAY_HOST, GATEWAY_PORT))
        server_socket.listen(10)

        logger.info(f"API Gateway started on {GATEWAY_HOST}:{GATEWAY_PORT}")
        logger.info(f"Backend: {APP_HOST}:{APP_PORT}")
        logger.info(f"Security: Rate limit={RATE_LIMIT_PER_MIN}/min, Brute-force threshold={BRUTE_FORCE_THRESHOLD}, DoS threshold={DOS_THRESHOLD}/min")
        print(f"\n[API Gateway] Listening on {GATEWAY_HOST}:{GATEWAY_PORT}")
        print(f"[API Gateway] Forwarding to {APP_HOST}:{APP_PORT}")
        print(f"[API Gateway] Logs -> {LOG_DIR}\n")

        try:
            while True:
                client_socket, address = server_socket.accept()
                thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            elapsed = time.time() - self.start_time
            logger.info(f"Gateway shutting down. Uptime: {elapsed:.0f}s, Requests: {self.total_requests}, Threats: {self.threats_detected}, Mitigations: {self.mitg_applied}")
            print("\n[API Gateway] Shutting down...")
        finally:
            server_socket.close()

APIGateway().start()

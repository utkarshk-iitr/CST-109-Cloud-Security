import socket
import threading
import time
from collections import defaultdict
from itertools import cycle
from common.config import *
from common.utils import *

gw_log = get_logger("Gateway", "gateway.log")
auth_log = get_logger("GW-Auth", "auth.log")
access_log = get_logger("GW-Access", "access.log")
threat_log = get_logger("GW-Threat", "threats.log")
mitg_log = get_logger("GW-Mitigation", "mitigation.log")

class APIGateway:
    def __init__(self):
        self.lock = threading.Lock()
        self.req_time = defaultdict(list)
        self.inv_cnt = defaultdict(int)
        self.blocked_ips = {}
        self.backends = cycle(BACKEND_SERVERS)

        self.perm = {"GET_PROFILE": {"admin", "user"}, "GET_ADMIN_REPORT": {"admin"}}

    def check_rate(self, client_ip):
        now = time.time()
        with self.lock:
            self.req_time[client_ip] = [ts for ts in self.req_time[client_ip] if now - ts < 60]
            if len(self.req_time[client_ip]) >= REQ_MIN:
                return False
            self.req_time[client_ip].append(now)
            return True

    def blocked(self, client_ip):
        now = time.time()
        with self.lock:
            until = self.blocked_ips.get(client_ip, 0)
            if until > now:
                return True, int(until - now)
            if until:
                del self.blocked_ips[client_ip]
            return False, 0

    def recorc_inv(self, client_ip):
        with self.lock:
            self.inv_cnt[client_ip] += 1
            count = self.inv_cnt[client_ip]
            if count >= INV_THRESHOLD:
                self.blocked_ips[client_ip] = time.time() + LOCK_SEC
                mitg_log.critical("IP BLOCKED | ip=%s reason=invalid_token threshold=%s duration=%ss",client_ip,INV_THRESHOLD,LOCK_SEC)
                return True
            return False

    def recorc_valid(self, client_ip):
        with self.lock:
            self.inv_cnt[client_ip] = 0

    def fwd(self, host, port, payload):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((host, port))
        send_json(sock, payload)
        response = recv_json(sock)
        sock.close()
        return response

    def handle_pub(self, request, client_ip):
        operation = request.get("operation")
        if operation not in {"REGISTER", "LOGIN"}:
            return None

        response = self.fwd(IAM_HOST, IAM_PORT, request)
        username = request.get("username", "")
        if operation == "LOGIN":
            if response.get("status") == "SUCCESS":
                auth_log.info("LOGIN SUCCESS | user=%s ip=%s", username, client_ip)
            else:
                auth_log.warning("LOGIN FAILED | user=%s ip=%s reason=%s",username,client_ip,response.get("message", "unknown"))
        return response

    def auth(self, request, client_ip):
        operation = request.get("operation")
        token = request.get("token", "")

        if not token:
            access_log.warning("UNAUTHORIZED | ip=%s op=%s reason=missing_token", client_ip, operation)
            threat_log.warning("THREAT | ip=%s op=%s type=missing_token", client_ip, operation)
            return None, {"status": "ERROR", "message": "Authentication required"}

        valid, payload = verify_jwt(token, JWT_SECRET)
        if not valid:
            blocked = self.recorc_inv(client_ip)
            access_log.warning("UNAUTHORIZED | ip=%s op=%s reason=%s",client_ip,operation,payload)
            threat_log.warning("THREAT | ip=%s op=%s type=invalid_token", client_ip, operation)
            if blocked:
                return None, {"status": "ERROR", "message": "IP blocked due to repeated invalid tokens"}
            return None, {"status": "ERROR", "message": "Invalid or expired token"}

        self.recorc_valid(client_ip)

        role = payload.get("role")
        if role not in self.perm.get(operation, set()):
            access_log.warning("UNAUTHORIZED | user=%s role=%s ip=%s op=%s reason=rbac",payload.get("sub"),role,client_ip,operation)
            threat_log.warning("THREAT | user=%s role=%s ip=%s op=%s type=unauthorized_access",payload.get("sub"),role,client_ip,operation)
            return None, {"status": "ERROR", "message": "Permission denied"}

        access_log.info("AUTHORIZED | user=%s role=%s ip=%s op=%s",payload.get("sub"),role,client_ip,operation)
        return payload, None

    def handle_client(self, conn, addr):
        client_ip = addr[0]

        blocked, remaining = self.blocked(client_ip)
        if blocked:
            send_json(conn, {"status": "ERROR", "message": f"IP blocked for {remaining} seconds"})
            conn.close()
            return

        if not self.check_rate(client_ip):
            threat_log.warning("THREAT | ip=%s type=rate_limit", client_ip)
            send_json(conn, {"status": "ERROR", "message": "Rate limit exceeded"})
            conn.close()
            return

        try:
            request = recv_json(conn)
            operation = request.get("operation", "UNKNOWN")
            gw_log.info("REQUEST | ip=%s op=%s", client_ip, operation)

            pub_resp = self.handle_pub(request, client_ip)
            if pub_resp is not None:
                send_json(conn, pub_resp)
                return

            claims, auth_error = self.auth(request, client_ip)
            if auth_error is not None:
                send_json(conn, auth_error)
                return

            backend = next(self.backends)
            back_req = dict(request)
            back_req["user"] = claims.get("sub")
            back_req["role"] = claims.get("role")

            back_resp = self.fwd(backend["host"], backend["port"], back_req)
            back_resp["served_by"] = backend["id"]
            send_json(conn, back_resp)
        except Exception as exc:
            gw_log.error("Error handling request from %s: %s", client_ip, exc)
            send_json(conn, {"status": "ERROR", "message": "Gateway internal error"})
        finally:
            conn.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((GATEWAY_HOST, GATEWAY_PORT))
        server.listen(30)

        gw_log.info("API Gateway started at %s:%s", GATEWAY_HOST, GATEWAY_PORT)
        gw_log.info("IAM backend at %s:%s", IAM_HOST, IAM_PORT)
        gw_log.info("Resource backends: %s", BACKEND_SERVERS)

        try:
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            gw_log.info("Gateway shutting down")
        finally:
            server.close()

APIGateway().start()

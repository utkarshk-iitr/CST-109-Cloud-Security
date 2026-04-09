import socket
import ssl
import threading
import time
from collections import defaultdict
from itertools import cycle
from config import *
from utils import *

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
        self.user_inv_cnt = defaultdict(int)
        self.user_blocked_until = {}
        self.user_access = defaultdict(list)
        self.user_node_restrict = {}
        self.backends = cycle(BACKEND_SERVERS)
        self.backend_ids = {backend["id"] for backend in BACKEND_SERVERS}
        initialize_key_ring()

        self.perm = {
            "GET_PROFILE": {"admin", "user"},
            "GET_ADMIN_REPORT": {"admin"},
            "SHOW_ENCRYPTED_RECORDS": {"admin"},
        }

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

    def record_invalid_token(self, client_ip):
        with self.lock:
            self.inv_cnt[client_ip] += 1
            count = self.inv_cnt[client_ip]
            if count >= INV_THRESHOLD:
                self.blocked_ips[client_ip] = time.time() + LOCK_SEC
                mitg_log.critical("IP BLOCKED | ip=%s reason=invalid_token threshold=%s duration=%ss",client_ip,INV_THRESHOLD,LOCK_SEC)
                return True
            return False

    def record_valid_token(self, client_ip):
        with self.lock:
            self.inv_cnt[client_ip] = 0

    def track_user_violation(self, username, reason, client_ip):
        with self.lock:
            self.user_inv_cnt[username] += 1
            count = self.user_inv_cnt[username]
            if count >= UNAUTH_THRESHOLD:
                self.user_blocked_until[username] = time.time() + LOCK_SEC
                self.user_node_restrict[username] = {
                    "deny_nodes": {"backend_2"},
                    "until": time.time() + LOCK_SEC,
                }
                mitg_log.critical(
                    "USER BLOCKED | user=%s ip=%s reason=%s threshold=%s LOCK_SEConds=%s",
                    username,
                    client_ip,
                    reason,
                    UNAUTH_THRESHOLD,
                    LOCK_SEC,
                )
                return True
            return False

    def is_user_blocked(self, username):
        now = time.time()
        with self.lock:
            until = self.user_blocked_until.get(username, 0)
            if until > now:
                return True, int(until - now)
            if until:
                self.user_blocked_until.pop(username, None)
            return False, 0

    def record_access_pattern(self, username, operation, client_ip):
        now = time.time()
        with self.lock:
            window = [ts for ts in self.user_access[username] if now - ts < 60]
            window.append(now)
            self.user_access[username] = window
            if len(window) >= UNUSUAL_ACCESS_PER_MIN:
                threat_log.critical(
                    "ALERT | user=%s ip=%s op=%s reason=unusual_access_frequency hits_per_min=%s",
                    username,
                    client_ip,
                    operation,
                    len(window),
                )
                self.user_node_restrict[username] = {
                    "deny_nodes": {"backend_2"},
                    "until": time.time() + LOCK_SEC,
                }

    def cleanup_state(self):
        while True:
            now = time.time()
            with self.lock:
                expired_ips = [ip for ip, until in self.blocked_ips.items() if until <= now]
                for ip in expired_ips:
                    self.blocked_ips.pop(ip, None)
                    self.inv_cnt[ip] = 0

                expired_users = [usr for usr, until in self.user_blocked_until.items() if until <= now]
                for usr in expired_users:
                    self.user_blocked_until.pop(usr, None)
                    self.user_inv_cnt[usr] = 0

                expired_restrict = [
                    usr
                    for usr, rule in self.user_node_restrict.items()
                    if rule.get("until", 0) <= now
                ]
                for usr in expired_restrict:
                    self.user_node_restrict.pop(usr, None)
            time.sleep(5)

    def rotate_keys_worker(self):
        while True:
            time.sleep(KEY_SEC)
            new_key_id = rotate_key()
            mitg_log.info("KEY ROTATION | new_key_id=%s interval_seconds=%s", new_key_id, KEY_SEC)

    def get_restricted_nodes(self, username):
        with self.lock:
            rule = self.user_node_restrict.get(username)
            if rule is None:
                return set()
            if rule.get("until", 0) <= time.time():
                self.user_node_restrict.pop(username, None)
                return set()
            return set(rule.get("deny_nodes", set()))

    def pick_backend(self, username):
        denied = self.get_restricted_nodes(username)
        for _ in range(len(BACKEND_SERVERS)):
            backend = next(self.backends)
            if backend["id"] not in denied:
                return backend
        return None

    def fwd(self, host, port, payload):
        sock = open_outbound_socket(host, port, timeout=8)
        send_json(sock, payload)
        response = recv_json(sock)
        sock.close()
        return response

    def handle_pub(self, request, client_ip):
        operation = request.get("operation")
        if operation not in {"REGISTER", "LOGIN", "RENEW_TOKEN"}:
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
            blocked = self.record_invalid_token(client_ip)
            access_log.warning("UNAUTHORIZED | ip=%s op=%s reason=%s",client_ip,operation,payload)
            threat_log.warning("THREAT | ip=%s op=%s type=invalid_token", client_ip, operation)
            if blocked:
                return None, {"status": "ERROR", "message": "IP blocked due to repeated invalid tokens"}
            return None, {"status": "ERROR", "message": "Invalid or expired token"}

        self.record_valid_token(client_ip)

        user = payload.get("sub", "unknown")
        user_blocked, remaining = self.is_user_blocked(user)
        if user_blocked:
            threat_log.warning("THREAT | user=%s ip=%s op=%s type=user_temporarily_blocked", user, client_ip, operation)
            return None, {"status": "ERROR", "message": f"User blocked for {remaining} seconds"}

        role = payload.get("role")
        if role not in self.perm.get(operation, set()):
            access_log.warning("UNAUTHORIZED | user=%s role=%s ip=%s op=%s reason=rbac",payload.get("sub"),role,client_ip,operation)
            threat_log.warning("THREAT | user=%s role=%s ip=%s op=%s type=unauthorized_access",payload.get("sub"),role,client_ip,operation)
            blocked = self.track_user_violation(user, "rbac", client_ip)
            if blocked:
                return None, {"status": "ERROR", "message": "User blocked due to repeated unauthorized access"}
            return None, {"status": "ERROR", "message": "Permission denied"}

        self.record_access_pattern(user, operation, client_ip)
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

            backend = self.pick_backend(claims.get("sub"))
            if backend is None:
                threat_log.critical("THREAT | user=%s ip=%s op=%s type=all_nodes_restricted", claims.get("sub"), client_ip, operation)
                send_json(conn, {"status": "ERROR", "message": "No backend available for this user"})
                return

            back_req = dict(request)
            back_req["user"] = claims.get("sub")
            back_req["role"] = claims.get("role")

            back_resp = self.fwd(backend["host"], backend["port"], back_req)
            back_resp["served_by"] = backend["id"]

            backend_identity = back_resp.get("server", backend["id"])
            if backend_identity not in self.backend_ids:
                threat_log.critical(
                    "ALERT | user=%s ip=%s op=%s reason=unknown_node backend=%s",
                    claims.get("sub"),
                    client_ip,
                    operation,
                    backend_identity,
                )

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
        tls_context = build_tls_server_context()

        cleanup_thread = threading.Thread(target=self.cleanup_state, daemon=True)
        cleanup_thread.start()

        key_rotation_thread = threading.Thread(target=self.rotate_keys_worker, daemon=True)
        key_rotation_thread.start()

        gw_log.info("API Gateway started at %s:%s", GATEWAY_HOST, GATEWAY_PORT)
        gw_log.info("IAM backend at %s:%s", IAM_HOST, IAM_PORT)
        gw_log.info("Resource backends: %s", BACKEND_SERVERS)
        if tls_context is not None:
            gw_log.info("TLS enabled for API Gateway and all forwarded service calls")

        try:
            while True:
                conn, addr = server.accept()
                if tls_context is not None:
                    try:
                        conn = tls_context.wrap_socket(conn, server_side=True)
                    except ssl.SSLError as exc:
                        gw_log.warning("TLS handshake failed from %s: %s", addr[0], exc)
                        conn.close()
                        continue
                thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            gw_log.info("Gateway shutting down")
        finally:
            server.close()

APIGateway().start()

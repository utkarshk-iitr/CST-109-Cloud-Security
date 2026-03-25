import socket
import sys
import threading
import time
from collections import defaultdict
from itertools import cycle
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from common.config import (
    BACKEND_SERVERS,
    BLOCK_IP_SECONDS,
    GATEWAY_HOST,
    GATEWAY_PORT,
    IAM_HOST,
    IAM_PORT,
    INVALID_TOKEN_THRESHOLD,
    JWT_SECRET,
    MAX_REQ_PER_MIN,
)
from common.jwt_utils import verify_jwt
from common.logger_utils import get_logger
from common.socket_utils import recv_json, send_json

gateway_log = get_logger("Gateway", "gateway.log")
auth_log = get_logger("GW-Auth", "auth.log")
access_log = get_logger("GW-Access", "access.log")
threat_log = get_logger("GW-Threat", "threats.log")
mitigation_log = get_logger("GW-Mitigation", "mitigation.log")


class APIGateway:
    def __init__(self):
        self.lock = threading.Lock()
        self.request_times = defaultdict(list)
        self.invalid_token_counts = defaultdict(int)
        self.blocked_ips = {}
        self.backends = cycle(BACKEND_SERVERS)

        self.permissions = {
            "GET_PROFILE": {"admin", "user"},
            "GET_ADMIN_REPORT": {"admin"},
        }

    def _check_rate_limit(self, client_ip):
        now = time.time()
        with self.lock:
            self.request_times[client_ip] = [
                ts for ts in self.request_times[client_ip] if now - ts < 60
            ]
            if len(self.request_times[client_ip]) >= MAX_REQ_PER_MIN:
                return False
            self.request_times[client_ip].append(now)
            return True

    def _is_ip_blocked(self, client_ip):
        now = time.time()
        with self.lock:
            until = self.blocked_ips.get(client_ip, 0)
            if until > now:
                return True, int(until - now)
            if until:
                del self.blocked_ips[client_ip]
            return False, 0

    def _record_invalid_token(self, client_ip):
        with self.lock:
            self.invalid_token_counts[client_ip] += 1
            count = self.invalid_token_counts[client_ip]
            if count >= INVALID_TOKEN_THRESHOLD:
                self.blocked_ips[client_ip] = time.time() + BLOCK_IP_SECONDS
                mitigation_log.critical(
                    "IP BLOCKED | ip=%s reason=invalid_token threshold=%s duration=%ss",
                    client_ip,
                    INVALID_TOKEN_THRESHOLD,
                    BLOCK_IP_SECONDS,
                )
                return True
            return False

    def _record_valid_token(self, client_ip):
        with self.lock:
            self.invalid_token_counts[client_ip] = 0

    def _forward(self, host, port, payload):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((host, port))
        send_json(sock, payload)
        response = recv_json(sock)
        sock.close()
        return response

    def _handle_public(self, request, client_ip):
        operation = request.get("operation")
        if operation not in {"REGISTER", "LOGIN"}:
            return None

        response = self._forward(IAM_HOST, IAM_PORT, request)
        username = request.get("username", "")
        if operation == "LOGIN":
            if response.get("status") == "SUCCESS":
                auth_log.info("LOGIN SUCCESS | user=%s ip=%s", username, client_ip)
            else:
                auth_log.warning(
                    "LOGIN FAILED | user=%s ip=%s reason=%s",
                    username,
                    client_ip,
                    response.get("message", "unknown"),
                )
        return response

    def _authorize(self, request, client_ip):
        operation = request.get("operation")
        token = request.get("token", "")

        if not token:
            access_log.warning("UNAUTHORIZED | ip=%s op=%s reason=missing_token", client_ip, operation)
            threat_log.warning("THREAT | ip=%s op=%s type=missing_token", client_ip, operation)
            return None, {"status": "ERROR", "message": "Authentication required"}

        valid, payload = verify_jwt(token, JWT_SECRET)
        if not valid:
            blocked = self._record_invalid_token(client_ip)
            access_log.warning(
                "UNAUTHORIZED | ip=%s op=%s reason=%s",
                client_ip,
                operation,
                payload,
            )
            threat_log.warning("THREAT | ip=%s op=%s type=invalid_token", client_ip, operation)
            if blocked:
                return None, {"status": "ERROR", "message": "IP blocked due to repeated invalid tokens"}
            return None, {"status": "ERROR", "message": "Invalid or expired token"}

        self._record_valid_token(client_ip)

        role = payload.get("role")
        if role not in self.permissions.get(operation, set()):
            access_log.warning(
                "UNAUTHORIZED | user=%s role=%s ip=%s op=%s reason=rbac",
                payload.get("sub"),
                role,
                client_ip,
                operation,
            )
            threat_log.warning(
                "THREAT | user=%s role=%s ip=%s op=%s type=unauthorized_access",
                payload.get("sub"),
                role,
                client_ip,
                operation,
            )
            return None, {"status": "ERROR", "message": "Permission denied"}

        access_log.info(
            "AUTHORIZED | user=%s role=%s ip=%s op=%s",
            payload.get("sub"),
            role,
            client_ip,
            operation,
        )
        return payload, None

    def _handle_client(self, conn, addr):
        client_ip = addr[0]

        blocked, remaining = self._is_ip_blocked(client_ip)
        if blocked:
            send_json(conn, {"status": "ERROR", "message": f"IP blocked for {remaining} seconds"})
            conn.close()
            return

        if not self._check_rate_limit(client_ip):
            threat_log.warning("THREAT | ip=%s type=rate_limit", client_ip)
            send_json(conn, {"status": "ERROR", "message": "Rate limit exceeded"})
            conn.close()
            return

        try:
            request = recv_json(conn)
            operation = request.get("operation", "UNKNOWN")
            gateway_log.info("REQUEST | ip=%s op=%s", client_ip, operation)

            public_response = self._handle_public(request, client_ip)
            if public_response is not None:
                send_json(conn, public_response)
                return

            claims, auth_error = self._authorize(request, client_ip)
            if auth_error is not None:
                send_json(conn, auth_error)
                return

            backend = next(self.backends)
            backend_request = dict(request)
            backend_request["user"] = claims.get("sub")
            backend_request["role"] = claims.get("role")

            backend_response = self._forward(backend["host"], backend["port"], backend_request)
            backend_response["served_by"] = backend["id"]
            send_json(conn, backend_response)
        except Exception as exc:
            gateway_log.error("Error handling request from %s: %s", client_ip, exc)
            send_json(conn, {"status": "ERROR", "message": "Gateway internal error"})
        finally:
            conn.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((GATEWAY_HOST, GATEWAY_PORT))
        server.listen(30)

        gateway_log.info("API Gateway started at %s:%s", GATEWAY_HOST, GATEWAY_PORT)
        gateway_log.info("IAM backend at %s:%s", IAM_HOST, IAM_PORT)
        gateway_log.info("Resource backends: %s", BACKEND_SERVERS)

        try:
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            gateway_log.info("Gateway shutting down")
        finally:
            server.close()


if __name__ == "__main__":
    APIGateway().start()

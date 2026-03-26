import hashlib
import os
import socket
import sys
import threading
import time

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from common.config import (ACCOUNT_LOCK_SECONDS,IAM_HOST,IAM_PORT,JWT_EXP_SECONDS,JWT_SECRET,MAX_LOGIN_ATTEMPTS)
from common.jwt_utils import create_jwt
from common.logger_utils import get_logger
from common.socket_utils import recv_json, send_json

app_log = get_logger("IAM", "iam_server.log")
auth_log = get_logger("IAM-Auth", "auth.log")
mitigation_log = get_logger("IAM-Mitigation", "mitigation.log")

class IAMServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.lock = threading.Lock()
        self.users = {}
        self._seed_users()

    def _seed_users(self):
        self._create_user("admin", "admin123", "admin")
        self._create_user("user1", "user123", "user")

    def _hash_password(self, password, salt):
        data = (salt + password).encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def _create_user(self, username, password, role):
        salt = os.urandom(16).hex()
        self.users[username] = {"salt": salt,"password_hash": self._hash_password(password, salt),"role": role,"failed_attempts": 0,"lock_until": 0}

    def _register(self, request, client_ip):
        username = request.get("username", "").strip()
        password = request.get("password", "")
        role = request.get("role", "user").strip().lower()

        if not username or not password:
            return {"status": "ERROR", "message": "Username and password are required"}

        if role not in ("user", "admin"):
            return {"status": "ERROR", "message": "Role must be admin or user"}

        with self.lock:
            if username in self.users:
                return {"status": "ERROR", "message": "Username already exists"}
            self._create_user(username, password, role)

        auth_log.info("REGISTER SUCCESS | user=%s role=%s ip=%s", username, role, client_ip)
        return {"status": "SUCCESS", "message": "Registration successful", "role": role}

    def _login(self, request, client_ip):
        username = request.get("username", "").strip()
        password = request.get("password", "")

        with self.lock:
            user = self.users.get(username)
            if not user:
                auth_log.warning("LOGIN FAILED | user=%s ip=%s reason=unknown_user", username, client_ip)
                return {"status": "ERROR", "message": "Invalid credentials"}

            now = int(time.time())
            lock_until = int(user.get("lock_until", 0))
            if now < lock_until:
                remaining = lock_until - now
                auth_log.warning("LOGIN BLOCKED | user=%s ip=%s reason=locked remaining=%ss",username,client_ip,remaining)
                return {"status": "ERROR","message": f"Account locked for {remaining} seconds"}

            expected = user["password_hash"]
            current = self._hash_password(password, user["salt"])
            if current != expected:
                user["failed_attempts"] += 1
                attempts = user["failed_attempts"]
                auth_log.warning("LOGIN FAILED | user=%s ip=%s reason=bad_password attempt=%s",username,client_ip,attempts)
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    user["lock_until"] = now + ACCOUNT_LOCK_SECONDS
                    mitigation_log.critical("ACCOUNT LOCKOUT | user=%s ip=%s attempts=%s lock_seconds=%s",username,client_ip,attempts,ACCOUNT_LOCK_SECONDS)
                    return {"status": "ERROR","message": f"Account locked for {ACCOUNT_LOCK_SECONDS} seconds"}
                return {"status": "ERROR", "message": "Invalid credentials"}

            user["failed_attempts"] = 0
            user["lock_until"] = 0
            token = create_jwt({"sub": username, "role": user["role"]}, JWT_SECRET, JWT_EXP_SECONDS)

        auth_log.info("LOGIN SUCCESS | user=%s role=%s ip=%s", username, user["role"], client_ip)
        return {"status": "SUCCESS","message": "Login successful","token": token,"role": user["role"],"expires_in": JWT_EXP_SECONDS}

    def _handle(self, conn, addr):
        client_ip = addr[0]
        try:
            request = recv_json(conn)
            operation = request.get("operation")
            if operation == "REGISTER":
                response = self._register(request, client_ip)
            elif operation == "LOGIN":
                response = self._login(request, client_ip)
            elif operation == "PING":
                response = {"status": "SUCCESS", "message": "IAM alive"}
            else:
                response = {"status": "ERROR", "message": "Unsupported IAM operation"}
            send_json(conn, response)
        except Exception as exc:
            app_log.error("Request handling error from %s: %s", client_ip, exc)
            send_json(conn, {"status": "ERROR", "message": "IAM internal error"})
        finally:
            conn.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(20)
        app_log.info("IAM server started at %s:%s", self.host, self.port)

        try:
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self._handle, args=(conn, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            app_log.info("IAM server shutting down")
        finally:
            server.close()

IAMServer(IAM_HOST, IAM_PORT).start()

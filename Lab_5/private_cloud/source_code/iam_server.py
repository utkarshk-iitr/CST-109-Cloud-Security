import hashlib
import os
import secrets
import socket
import ssl
import threading
import time
from config import *
from utils import *

app_log = get_logger("IAM", "iam_server.log")
auth_log = get_logger("IAM-Auth", "auth.log")
mitg_log = get_logger("IAM-Mitigation", "mitigation.log")

class IAMServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.lock = threading.Lock()
        self.users = {}
        self.refresh_tokens = {}
        self.seed_usr()

    def seed_usr(self):
        self.create_usr("admin", "admin123", "admin")
        self.create_usr("user1", "user123", "user")

    def hash_pw(self, password, salt):
        data = (salt + password).encode("utf-8")
        return hashlib.sha256(data).hexdigest()

    def create_usr(self, username, password, role):
        salt = os.urandom(16).hex()
        self.users[username] = {"salt": salt,"password_hash": self.hash_pw(password, salt),"role": role,"failed_attempts": 0,"lock_until": 0}

    def register(self, request, client_ip):
        un = request.get("username", "").strip()
        pw = request.get("password", "")
        role = request.get("role", "user").strip().lower()

        if not un or not pw:
            return {"status": "ERROR", "message": "Username and password are required"}

        if role not in ("user", "admin"):
            return {"status": "ERROR", "message": "Role must be admin or user"}

        with self.lock:
            if un in self.users:
                return {"status": "ERROR", "message": "Username already exists"}
            self.create_usr(un, pw, role)

        auth_log.info("REGISTER SUCCESS | user=%s role=%s ip=%s", un, role, client_ip)
        return {"status": "SUCCESS", "message": "Registration successful", "role": role}

    def login(self, request, client_ip):
        un = request.get("username", "").strip()
        pw = request.get("password", "")

        with self.lock:
            user = self.users.get(un)
            if not user:
                auth_log.warning("LOGIN FAILED | user=%s ip=%s reason=unknown_user", un, client_ip)
                return {"status": "ERROR", "message": "Invalid credentials"}

            now = int(time.time())
            lock_until = int(user.get("lock_until", 0))
            if now < lock_until:
                remaining = lock_until - now
                auth_log.warning("LOGIN BLOCKED | user=%s ip=%s reason=locked remaining=%ss",un,client_ip,remaining)
                return {"status": "ERROR","message": f"Account locked for {remaining} seconds"}

            expected = user["password_hash"]
            current = self.hash_pw(pw, user["salt"])
            if current != expected:
                user["failed_attempts"] += 1
                attempts = user["failed_attempts"]
                auth_log.warning("LOGIN FAILED | user=%s ip=%s reason=bad_password attempt=%s",un,client_ip,attempts)
                if attempts >= MAX_LOGIN_ATTEMPTS:
                    user["lock_until"] = now + LOCK_SEC
                    mitg_log.critical("ACCOUNT LOCKOUT | user=%s ip=%s attempts=%s lock_seconds=%s",un,client_ip,attempts,LOCK_SEC)
                    return {"status": "ERROR","message": f"Account locked for {LOCK_SEC} seconds"}
                return {"status": "ERROR", "message": "Invalid credentials"}

            user["failed_attempts"] = 0
            user["lock_until"] = 0
            access_token, refresh_token = self.issue_tokens(un, user["role"])

        auth_log.info("LOGIN SUCCESS | user=%s role=%s ip=%s", un, user["role"], client_ip)
        return {
            "status": "SUCCESS",
            "message": "Login successful",
            "token": access_token,
            "refresh_token": refresh_token,
            "role": user["role"],
            "expires_in": JWT_EXP,
            "refresh_expires_in": REFRESH_EXP,
        }

    def issue_tokens(self, username, role):
        access_token = create_jwt({"sub": username, "role": role}, JWT_SECRET, JWT_EXP)
        refresh_token = secrets.token_urlsafe(48)
        refresh_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
        self.refresh_tokens[refresh_hash] = {
            "username": username,
            "role": role,
            "exp": int(time.time()) + REFRESH_EXP,
        }
        return access_token, refresh_token

    def renew_token(self, request, client_ip):
        refresh_token = request.get("refresh_token", "")
        if not refresh_token:
            return {"status": "ERROR", "message": "Refresh token required"}

        with self.lock:
            refresh_hash = hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
            session = self.refresh_tokens.get(refresh_hash)
            if session is None:
                auth_log.warning("TOKEN RENEW FAILED | ip=%s reason=unknown_refresh", client_ip)
                return {"status": "ERROR", "message": "Invalid refresh token"}

            if int(time.time()) >= int(session["exp"]):
                self.refresh_tokens.pop(refresh_hash, None)
                auth_log.warning("TOKEN RENEW FAILED | ip=%s user=%s reason=refresh_expired", client_ip, session.get("username"))
                return {"status": "ERROR", "message": "Refresh token expired"}

            username = session["username"]
            role = session["role"]
            self.refresh_tokens.pop(refresh_hash, None)
            access_token, new_refresh_token = self.issue_tokens(username, role)

        auth_log.info("TOKEN RENEW SUCCESS | user=%s ip=%s", username, client_ip)
        return {
            "status": "SUCCESS",
            "message": "Token renewed",
            "token": access_token,
            "refresh_token": new_refresh_token,
            "expires_in": JWT_EXP,
            "refresh_expires_in": REFRESH_EXP,
        }

    def handle_client(self, conn, addr):
        client_ip = addr[0]
        try:
            request = recv_json(conn)
            operation = request.get("operation")
            if operation == "REGISTER":
                response = self.register(request, client_ip)
            elif operation == "LOGIN":
                response = self.login(request, client_ip)
            elif operation == "RENEW_TOKEN":
                response = self.renew_token(request, client_ip)
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
        tls_context = build_tls_server_context()
        app_log.info("IAM server started at %s:%s", self.host, self.port)
        if tls_context is not None:
            app_log.info("TLS enabled for IAM server")

        try:
            while True:
                conn, addr = server.accept()
                if tls_context is not None:
                    try:
                        conn = tls_context.wrap_socket(conn, server_side=True)
                    except ssl.SSLError as exc:
                        app_log.warning("TLS handshake failed from %s: %s", addr[0], exc)
                        conn.close()
                        continue
                thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            app_log.info("IAM server shutting down")
        finally:
            server.close()

IAMServer(IAM_HOST, IAM_PORT).start()

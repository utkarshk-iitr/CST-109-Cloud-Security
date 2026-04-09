import json
import os
import socket
import ssl
import sys
import threading
import time
from cryptography.fernet import Fernet
from common.config import STORAGE_DIR
from common.key_manager import get_active_key, get_all_keys, get_key, initialize_key_ring
from common.utils import *


class BackServer:
    def __init__(self, server_id, host, port):
        self.server_id = server_id
        self.host = host
        self.port = port
        self.log = get_logger(f"Backend-{server_id}", f"{server_id}.log")
        self.store_lock = threading.Lock()
        self.node_storage_dir = os.path.join(STORAGE_DIR, self.server_id)
        self.store_file = os.path.join(self.node_storage_dir, "encrypted_records.json")
        initialize_key_ring()
        self.bootstrap_store()

    def bootstrap_store(self):
        os.makedirs(self.node_storage_dir, exist_ok=True)
        with self.store_lock:
            if os.path.exists(self.store_file):
                return

            seed_payload = {
                "profiles": {
                    "admin": self.encrypt_record({
                        "message": f"Hello admin, profile data from {self.server_id}",
                        "timestamp": int(time.time()),
                    }),
                    "user1": self.encrypt_record({
                        "message": f"Hello user1, profile data from {self.server_id}",
                        "timestamp": int(time.time()),
                    }),
                },
                "admin_report": self.encrypt_record({
                    "active_users": 7,
                    "security_alerts": 2,
                    "uptime_minutes": 123,
                }),
            }
            self.save_store(seed_payload)
            self.log.info("Encrypted at-rest store initialized for %s", self.server_id)

    def load_store(self):
        if not os.path.exists(self.store_file):
            return {"profiles": {}, "admin_report": {}}
        with open(self.store_file, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def save_store(self, payload):
        with open(self.store_file, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def encrypt_record(self, payload):
        key_id, key = get_active_key()
        cipher = Fernet(key)
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ciphertext = cipher.encrypt(raw).decode("ascii")
        return {"key_id": key_id, "ciphertext": ciphertext}

    def decrypt_record(self, encrypted_record):
        key_id = encrypted_record.get("key_id")
        ciphertext = encrypted_record.get("ciphertext", "")

        candidate_keys = []
        if key_id:
            key = get_key(key_id)
            if key is not None:
                candidate_keys.append((key_id, key))

        for candidate_id, candidate_key in get_all_keys().items():
            if candidate_id != key_id:
                candidate_keys.append((candidate_id, candidate_key))

        for candidate_id, candidate_key in candidate_keys:
            try:
                cipher = Fernet(candidate_key)
                raw = cipher.decrypt(ciphertext.encode("ascii")).decode("utf-8")
                return json.loads(raw), candidate_id
            except Exception:
                continue

        return None, None

    def maybe_reencrypt(self, payload, used_key_id):
        active_key_id, _ = get_active_key()
        if used_key_id == active_key_id:
            return None
        return self.encrypt_record(payload)

    def handle_req(self, request):
        operation = request.get("operation")
        user = request.get("user", "unknown")
        role = request.get("role", "unknown")

        if operation == "GET_PROFILE":
            with self.store_lock:
                store = self.load_store()
                profiles = store.setdefault("profiles", {})
                if user not in profiles:
                    profiles[user] = self.encrypt_record({
                        "message": f"Hello {user}, profile data from {self.server_id}",
                        "timestamp": int(time.time()),
                    })
                    self.save_store(store)

                payload, used_key = self.decrypt_record(profiles[user])
                if payload is None:
                    self.log.error("Decrypt failed for user profile | user=%s server=%s", user, self.server_id)
                    return {"status": "ERROR", "message": "Encrypted data could not be decrypted"}

                refreshed = self.maybe_reencrypt(payload, used_key)
                if refreshed is not None:
                    profiles[user] = refreshed
                    self.save_store(store)

            self.log.info("AUTHORIZED | user=%s role=%s op=%s", user, role, operation)
            return {
                "status": "SUCCESS",
                "server": self.server_id,
                "data": payload,
                "at_rest_encryption": "enabled",
            }

        if operation == "GET_ADMIN_REPORT":
            if role != "admin":
                self.log.warning("UNAUTHORIZED | user=%s role=%s op=%s", user, role, operation)
                return {"status": "ERROR", "message": "Permission denied"}

            with self.store_lock:
                store = self.load_store()
                encrypted_report = store.get("admin_report", {})
                payload, used_key = self.decrypt_record(encrypted_report)
                if payload is None:
                    self.log.error("Decrypt failed for admin report | server=%s", self.server_id)
                    return {"status": "ERROR", "message": "Encrypted report could not be decrypted"}

                refreshed = self.maybe_reencrypt(payload, used_key)
                if refreshed is not None:
                    store["admin_report"] = refreshed
                    self.save_store(store)

            self.log.info("AUTHORIZED | user=%s role=%s op=%s", user, role, operation)
            return {
                "status": "SUCCESS",
                "server": self.server_id,
                "data": payload,
                "at_rest_encryption": "enabled",
            }

        if operation == "SHOW_ENCRYPTED_RECORDS":
            if role != "admin":
                self.log.warning("UNAUTHORIZED | user=%s role=%s op=%s", user, role, operation)
                return {"status": "ERROR", "message": "Permission denied"}

            with self.store_lock:
                store = self.load_store()
            return {"status": "SUCCESS", "server": self.server_id, "encrypted_store": store}

        if operation == "PING":
            return {"status": "SUCCESS", "server": self.server_id, "message": "Backend alive"}

        return {"status": "ERROR", "message": "Unsupported backend operation"}

    def handle_client(self, conn, addr):
        client_ip = addr[0]
        try:
            request = recv_json(conn)
            response = self.handle_req(request)
            send_json(conn, response)
        except Exception as exc:
            self.log.error("Request handling error from %s: %s", client_ip, exc)
            send_json(conn, {"status": "ERROR", "message": "Backend internal error"})
        finally:
            conn.close()

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(20)
        tls_context = build_tls_server_context()
        self.log.info("%s started at %s:%s", self.server_id, self.host, self.port)
        if tls_context is not None:
            self.log.info("TLS enabled for backend node %s", self.server_id)

        try:
            while True:
                conn, addr = server.accept()
                if tls_context is not None:
                    try:
                        conn = tls_context.wrap_socket(conn, server_side=True)
                    except ssl.SSLError as exc:
                        self.log.warning("TLS handshake failed from %s: %s", addr[0], exc)
                        conn.close()
                        continue
                thread = threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            self.log.info("%s shutting down", self.server_id)
        finally:
            server.close()

if len(sys.argv) != 3:
    print("Usage: python3 backend_servers/backend_server.py <id> <port>")
    sys.exit(1)

server_id = f"backend_{sys.argv[1]}"
host = "127.0.0.1"
port = int(sys.argv[2])
BackServer(server_id, host, port).start()

import base64
import hashlib
import hmac
import json
import logging
import os
import socket
import ssl
import time
from config import *
import threading
from cryptography.fernet import Fernet

_lock = threading.Lock()

def chhota_write(path, payload):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    os.replace(tmp_path, path)

def load_ring():
    if not os.path.exists(KEY_RING_FILE):
        return None
    with open(KEY_RING_FILE, "r", encoding="utf-8") as handle:
        return json.load(handle)

def init_key_ring():
    os.makedirs(SECURITY_DIR, exist_ok=True)
    with _lock:
        ring = load_ring()
        if ring:
            return ring

        key_id = f"key-{int(time.time())}"
        ring = {
            "active_key_id": key_id,
            "keys": {key_id: Fernet.generate_key().decode("ascii")},
            "rotated_at": int(time.time()),
        }
        chhota_write(KEY_RING_FILE, ring)
        return ring

def get_active_key():
    ring = init_key_ring()
    key_id = ring["active_key_id"]
    key = ring["keys"][key_id].encode("ascii")
    return key_id, key

def get_key(key_id):
    ring = init_key_ring()
    key = ring["keys"].get(key_id)
    if key is None:
        return None
    return key.encode("ascii")

def get_all_keys():
    ring = init_key_ring()
    return {key_id: key.encode("ascii") for key_id, key in ring["keys"].items()}

def rotate_key():
    with _lock:
        ring = init_key_ring()
        new_key_id = f"key-{int(time.time())}"
        ring["keys"][new_key_id] = Fernet.generate_key().decode("ascii")
        ring["active_key_id"] = new_key_id
        ring["rotated_at"] = int(time.time())

        ordered = sorted(ring["keys"].keys(), key=lambda value: int(value.split("-")[1]))
        while len(ordered) > KEY_RING_RETAIN:
            to_remove = ordered.pop(0)
            if to_remove != ring["active_key_id"]:
                ring["keys"].pop(to_remove, None)

        chhota_write(KEY_RING_FILE, ring)
        return new_key_id

def b64url_enc(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")

def b64url_dec(encoded):
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode((encoded + padding).encode("ascii"))

def create_jwt(payload, secret, expires_in):
    now = int(time.time())
    body = dict(payload)
    body["iat"] = now
    body["exp"] = now + int(expires_in)

    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_enc(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_enc(json.dumps(body, separators=(",", ":")).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = b64url_enc(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"

def verify_jwt(token, secret):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False, "Malformed token"

        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual = b64url_dec(signature_b64)

        if not hmac.compare_digest(expected, actual):
            return False, "Invalid signature"

        payload = json.loads(b64url_dec(payload_b64).decode("utf-8"))
        now = int(time.time())
        if now >= int(payload.get("exp", 0)):
            return False, "Token expired"

        return True, payload
    except Exception:
        return False, "Invalid token"

def build_srvr():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=TLS_CERT_FILE, keyfile=TLS_KEY_FILE)
    return context

TLS_VERIFY_SERVER = False
def build_clnt():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if TLS_VERIFY_SERVER:
        context.load_verify_locations(cafile=TLS_CERT_FILE)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context

def open_outbound_socket(host, port, timeout=8):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))

    client_tls = build_clnt()
    if client_tls is not None:
        return client_tls.wrap_socket(sock, server_hostname="localhost")
    return sock

LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

def get_logger(name, filename, level=logging.INFO):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    os.makedirs(LOG_DIR, exist_ok=True)

    file_handler = logging.FileHandler(os.path.join(LOG_DIR, filename))
    stream_handler = logging.StreamHandler()

    formatter = logging.Formatter(LOG_FORMAT)
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger

def send_json(sock, payload):
    message = json.dumps(payload).encode("utf-8")
    sock.sendall(message)

def recv_json(sock, max_bytes=65536):
    data = sock.recv(max_bytes)
    if not data:
        return {}
    return json.loads(data.decode("utf-8"))
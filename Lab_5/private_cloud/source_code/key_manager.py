import json
import os
import threading
import time
from cryptography.fernet import Fernet
from common.config import KEY_RING_FILE, KEY_RING_RETAIN, SECURITY_DIR

_lock = threading.Lock()


def _atomic_write(path, payload):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    os.replace(tmp_path, path)


def _load_ring_from_disk():
    if not os.path.exists(KEY_RING_FILE):
        return None
    with open(KEY_RING_FILE, "r", encoding="utf-8") as handle:
        return json.load(handle)


def initialize_key_ring():
    os.makedirs(SECURITY_DIR, exist_ok=True)
    with _lock:
        ring = _load_ring_from_disk()
        if ring:
            return ring

        key_id = f"key-{int(time.time())}"
        ring = {
            "active_key_id": key_id,
            "keys": {key_id: Fernet.generate_key().decode("ascii")},
            "rotated_at": int(time.time()),
        }
        _atomic_write(KEY_RING_FILE, ring)
        return ring


def _load_ring():
    return initialize_key_ring()


def get_active_key():
    ring = _load_ring()
    key_id = ring["active_key_id"]
    key = ring["keys"][key_id].encode("ascii")
    return key_id, key


def get_key(key_id):
    ring = _load_ring()
    key = ring["keys"].get(key_id)
    if key is None:
        return None
    return key.encode("ascii")


def get_all_keys():
    ring = _load_ring()
    return {key_id: key.encode("ascii") for key_id, key in ring["keys"].items()}


def rotate_key():
    with _lock:
        ring = _load_ring()
        new_key_id = f"key-{int(time.time())}"
        ring["keys"][new_key_id] = Fernet.generate_key().decode("ascii")
        ring["active_key_id"] = new_key_id
        ring["rotated_at"] = int(time.time())

        ordered = sorted(ring["keys"].keys(), key=lambda value: int(value.split("-")[1]))
        while len(ordered) > KEY_RING_RETAIN:
            to_remove = ordered.pop(0)
            if to_remove != ring["active_key_id"]:
                ring["keys"].pop(to_remove, None)

        _atomic_write(KEY_RING_FILE, ring)
        return new_key_id

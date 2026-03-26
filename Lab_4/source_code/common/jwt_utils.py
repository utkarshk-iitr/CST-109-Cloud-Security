import base64
import hashlib
import hmac
import json
import time

def _b64url_encode(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded):
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode((encoded + padding).encode("ascii"))


def create_jwt(payload, secret, expires_in):
    now = int(time.time())
    body = dict(payload)
    body["iat"] = now
    body["exp"] = now + int(expires_in)

    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(body, separators=(",", ":")).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"

def verify_jwt(token, secret):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False, "Malformed token"

        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        actual = _b64url_decode(signature_b64)

        if not hmac.compare_digest(expected, actual):
            return False, "Invalid signature"

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        now = int(time.time())
        if now >= int(payload.get("exp", 0)):
            return False, "Token expired"

        return True, payload
    except Exception:
        return False, "Invalid token"

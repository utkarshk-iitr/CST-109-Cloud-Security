import json


def send_json(sock, payload):
    message = json.dumps(payload).encode("utf-8")
    sock.sendall(message)


def recv_json(sock, max_bytes=65536):
    data = sock.recv(max_bytes)
    if not data:
        return {}
    return json.loads(data.decode("utf-8"))

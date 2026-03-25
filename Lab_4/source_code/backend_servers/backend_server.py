import socket
import sys
import threading
import os
import time

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from common.logger_utils import get_logger
from common.socket_utils import recv_json, send_json


class BackendServer:
    def __init__(self, server_id, host, port):
        self.server_id = server_id
        self.host = host
        self.port = port
        self.log = get_logger(f"Backend-{server_id}", f"{server_id}.log")

    def _handle_business_request(self, request):
        operation = request.get("operation")
        user = request.get("user", "unknown")
        role = request.get("role", "unknown")

        if operation == "GET_PROFILE":
            self.log.info("AUTHORIZED | user=%s role=%s op=%s", user, role, operation)
            return {
                "status": "SUCCESS",
                "server": self.server_id,
                "data": {
                    "message": f"Hello {user}, profile data from {self.server_id}",
                    "timestamp": int(time.time()),
                },
            }

        if operation == "GET_ADMIN_REPORT":
            if role != "admin":
                self.log.warning("UNAUTHORIZED | user=%s role=%s op=%s", user, role, operation)
                return {"status": "ERROR", "message": "Permission denied"}
            self.log.info("AUTHORIZED | user=%s role=%s op=%s", user, role, operation)
            return {
                "status": "SUCCESS",
                "server": self.server_id,
                "data": {
                    "active_users": 7,
                    "security_alerts": 2,
                    "uptime_minutes": 123,
                },
            }

        if operation == "PING":
            return {"status": "SUCCESS", "server": self.server_id, "message": "Backend alive"}

        return {"status": "ERROR", "message": "Unsupported backend operation"}

    def _handle_client(self, conn, addr):
        client_ip = addr[0]
        try:
            request = recv_json(conn)
            response = self._handle_business_request(request)
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
        self.log.info("%s started at %s:%s", self.server_id, self.host, self.port)

        try:
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            self.log.info("%s shutting down", self.server_id)
        finally:
            server.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 backend_servers/backend_server.py <id> <port>")
        sys.exit(1)

    server_id = f"backend_{sys.argv[1]}"
    host = "127.0.0.1"
    port = int(sys.argv[2])
    BackendServer(server_id, host, port).start()

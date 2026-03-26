import json
import socket
import sys
import time
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from common.config import GATEWAY_HOST, GATEWAY_PORT
from common.socket_utils import recv_json, send_json


class IAMClient:
    def __init__(self):
        self.token = ""
        self.username = ""
        self.role = ""

    def _send(self, payload):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            sock.connect((GATEWAY_HOST, GATEWAY_PORT))
            send_json(sock, payload)
            response = recv_json(sock)
            sock.close()
            return response
        except Exception as exc:
            return {"status": "ERROR", "message": f"Connection error: {exc}"}

    def register(self):
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        role = input("Role (user/admin, default user): ").strip().lower() or "user"

        response = self._send({"operation": "REGISTER","username": username,"password": password,"role": role})
        print(json.dumps(response, indent=2))

    def login(self):
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        response = self._send({"operation": "LOGIN","username": username,"password": password})

        if response.get("status") == "SUCCESS":
            self.token = response.get("token", "")
            self.username = username
            self.role = response.get("role", "")
        print(json.dumps(response, indent=2))

    def get_profile(self):
        response = self._send({"operation": "GET_PROFILE","token": self.token})
        print(json.dumps(response, indent=2))

    def get_admin_report(self):
        response = self._send({"operation": "GET_ADMIN_REPORT","token": self.token})
        print(json.dumps(response, indent=2))

    def brute_force_simulation(self):
        target_user = input("Target username (default admin): ").strip() or "admin"
        attempts = int(input("Attempts (default 10): ").strip() or "10")

        passwords = ["pehla","123456","password","nawab","hello","indian","welcome","qwerty","abc123","hecker"]

        print("\nBrute-force login simulation\n")
        for idx in range(attempts):
            pwd = passwords[idx % len(passwords)]
            response = self._send({"operation": "LOGIN","username": target_user,"password": pwd})
            print(f"Attempt {idx + 1}: {pwd} -> {response.get('status')} | {response.get('message')}")
            if "locked" in str(response.get("message", "")).lower():
                print("Mitigation triggered: Account lockout is active.")
                break
            time.sleep(0.1)

    def invalid_token_attack(self):
        print("\nInvalid/tampered token simulation\n")
        fake_tokens = ["invalid.token.value","abc.def.ghi","tampered.payload.signature","eyJhbGciOiJIUzI1NiJ9.invalid.sig","","expired.token.format"]

        for idx, token in enumerate(fake_tokens, start=1):
            response = self._send({"operation": "GET_ADMIN_REPORT","token": token})
            print(f"Test {idx}: token='{token[:20]}' -> {response.get('status')} | {response.get('message')}")
            time.sleep(0.1)

    def token_expiry_demo(self):
        print("This system uses short token expiry by default. Wait for expiry then call a route.")
        input("Press Enter to continue and test with your current token...")
        response = self._send({"operation": "GET_PROFILE","token": self.token})
        print(json.dumps(response, indent=2))


def print_menu(client):
    print("\n" + "-" * 21)
    print("IAM Distributed System Client")
    if client.username:
        print(f"Logged in as: {client.username} ({client.role})")
    print("1. Register")
    print("2. Login")
    print("3. Access protected route: GET_PROFILE")
    print("4. Access admin-only route: GET_ADMIN_REPORT")
    print("5. Attack simulation: Brute-force login")
    print("6. Attack simulation: Invalid/tampered token")
    print("7. Token expiry demo")
    print("8. Exit")

client = IAMClient()

while True:
    print_menu(client)
    choice = input("Enter choice: ").strip()

    if choice == "1":
        client.register()
    elif choice == "2":
        client.login()
    elif choice == "3":
        client.get_profile()
    elif choice == "4":
        client.get_admin_report()
    elif choice == "5":
        client.brute_force_simulation()
    elif choice == "6":
        client.invalid_token_attack()
    elif choice == "7":
        client.token_expiry_demo()
    elif choice == "8":            
        print("Tata")
        break
    else:
        print("Invalid option")

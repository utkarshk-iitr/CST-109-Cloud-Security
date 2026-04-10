import json
import time
from config import *
from utils import *

class Client:
    def __init__(self):
        self.token = ""
        self.refresh_token = ""
        self.username = ""
        self.role = ""
        self.last_renew = 0

    def send(self, payload):
        try:
            sock = open_outbound_socket(GATEWAY_HOST, GATEWAY_PORT, timeout=8)
            send_json(sock, payload)
            response = recv_json(sock)
            sock.close()
            return response
        except Exception as exc:
            return {"status": "ERROR", "message": f"Connection error: {exc}"}

    def register(self):
        ussr = input("Username: ").strip()
        pw = input("Password: ").strip()
        role = input("Role (user/admin, default user): ").strip().lower() or "user"

        response = self.send({"operation": "REGISTER","username": ussr,"password": pw,"role": role})
        print(json.dumps(response, indent=2))

    def login(self):
        ussr = input("Username: ").strip()
        pw = input("Password: ").strip()

        resp = self.send({"operation": "LOGIN","username": ussr,"password": pw})

        if resp.get("status") == "SUCCESS":
            self.token = resp.get("token", "")
            self.refresh_token = resp.get("refresh_token", "")
            self.username = ussr
            self.role = resp.get("role", "")
            self.last_renew = int(time.time())
        print(json.dumps(resp, indent=2))

    def renew_token(self):
        if not self.refresh_token:
            return

        resp = self.send({"operation": "RENEW_TOKEN", "refresh_token": self.refresh_token})
        if resp.get("status") == "SUCCESS":
            self.token = resp.get("token", self.token)
            self.refresh_token = resp.get("refresh_token", self.refresh_token)
            self.last_renew = int(time.time())
            print("Token renewed successfully.")
            print(json.dumps(resp, indent=2))
        else:
            print(f"Token renew failed: {resp.get('message')}")

    def renew_again(self):
        if not self.token or not self.refresh_token:
            return

        now = int(time.time())
        if now - self.last_renew >= RENEW_TIME:
            self.renew_token()

    def get_profile(self):
        self.renew_again()
        resp = self.send({"operation": "GET_PROFILE","token": self.token})
        print(json.dumps(resp, indent=2))

    def get_admin_report(self):
        self.renew_again()
        resp = self.send({"operation": "GET_ADMIN_REPORT","token": self.token})
        print(json.dumps(resp, indent=2))

    def show_enc_records(self):
        self.renew_again()
        resp = self.send({"operation": "SHOW_ENC_REC", "token": self.token})
        print(json.dumps(resp, indent=2))

    def brute_force(self):
        target_user = input("Target username (default admin): ").strip() or "admin"
        attempts = int(input("Attempts (default 10): ").strip() or "10")

        passwords = ["ipl","pehla","123456","password","nawab","hello","indian","welcome","qwerty","abc123","hecker"]

        print("\nBrute-force login simulation\n")
        for idx in range(attempts):
            pwd = passwords[idx % len(passwords)]
            resp = self.send({"operation": "LOGIN","username": target_user,"password": pwd})
            print(f"Attempt {idx + 1}: {pwd} -> {resp.get('status')} | {resp.get('message')}")
            if "locked" in str(resp.get("message", "")).lower():
                print("Mitigation triggered: Account lockout is active.")
                break
            time.sleep(0.1)

    def inv_token(self):
        print("\nInvalid/tampered token simulation\n")
        fake_tokens = ["invalid.token.value","abc.def.ghi","tampered.payload.signature","eyJhbGciOiJIUzI1NiJ9.invalid.sig","","expired.token.format"]

        for idx, token in enumerate(fake_tokens, start=1):
            resp = self.send({"operation": "GET_ADMIN_REPORT","token": token})
            print(f"Test {idx}: token='{token[:20]}' -> {resp.get('status')} | {resp.get('message')}")
            time.sleep(0.1)

def print_menu(client):
    print("\n" + "-" * 21)
    print("IAM Distributed System Client")
    if client.username:
        print(f"Logged in as: {client.username} ({client.role})")
    print("1. Register")
    print("2. Login")
    print("3. Access protected route: GET_PROFILE")
    print("4. Access admin-only route: GET_ADMIN_REPORT")
    print("5. Show encrypted node data (admin only)")
    print("6. Renew token now")
    print("7. Attack simulation: Brute-force login")
    print("8. Attack simulation: Invalid/tampered token")
    print("9. Exit")

client = Client()

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
        client.show_enc_records()
    elif choice == "6":
        client.renew_token()
    elif choice == "7":
        client.brute_force()
    elif choice == "8":
        client.inv_token()
    elif choice == "9":
        print("Tata")
        break
    else:
        print("Invalid option")

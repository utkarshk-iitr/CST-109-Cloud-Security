import argparse
import json
import socket
import requests
from config import *

def web_list(base_url):
    response = requests.get(f"{base_url}/employees", timeout=8)
    print(response.status_code)
    print(json.dumps(response.json(), indent=2))

def web_add(base_url, id,name, email):
    response = requests.post(f"{base_url}/employees",json={"id": id, "name": name, "email": email},timeout=8)
    print(response.status_code)
    print(json.dumps(response.json(), indent=2))

def direct_db_test(db_host, db_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        sock.connect((db_host, db_port))
        print("Direct client -> DB TCP connect succeeded")
    except Exception as exc:
        print(f"Direct client -> DB blocked or unreachable: {exc}")
    finally:
        sock.close()

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=["web-list", "web-add", "direct-db-test"])
    args = parser.parse_args()

    if args.mode == "web-list":
        web_list(f"http://{WEB_HOST}:{WEB_PORT}")
    elif args.mode == "web-add":
        id = int(input("Enter ID: "))
        name = input("Enter name: ")
        email = input("Enter email: ")
        web_add(f"http://{WEB_HOST}:{WEB_PORT}", id,name, email)
    elif args.mode == "direct-db-test":
        direct_db_test(DB_HOST, DB_PORT)

run()
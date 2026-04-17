import argparse
import json
import socket
import requests

def web_list(base_url):
    response = requests.get(f"{base_url}/employees", timeout=8)
    print(response.status_code)
    print(json.dumps(response.json(), indent=2))

def web_add(base_url, name, email):
    response = requests.post(f"{base_url}/employees",json={"name": name, "email": email},timeout=8)
    print(response.status_code)
    print(json.dumps(response.json(), indent=2))

def direct_db_test(db_host, db_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((db_host, db_port))
        print("Direct client -> DB TCP connect succeeded")
    except Exception as exc:
        print(f"Direct client -> DB blocked or unreachable: {exc}")
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--mode", required=True, choices=["web-list", "web-add", "direct-db-test"])
    parser.add_argument("--name", default="charlie")
    parser.add_argument("--email", default="charlie@example.com")
    parser.add_argument("--db-host", default="127.0.0.1")
    parser.add_argument("--db-port", type=int, default=3306)
    args = parser.parse_args()

    if args.mode == "web-list":
        web_list(args.base_url)
    elif args.mode == "web-add":
        web_add(args.base_url, args.name, args.email)
    elif args.mode == "direct-db-test":
        direct_db_test(args.db_host, args.db_port)

main()

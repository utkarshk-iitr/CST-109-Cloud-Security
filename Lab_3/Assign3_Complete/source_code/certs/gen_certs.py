import os
import subprocess
import sys

CERT_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_FILE  = os.path.join(CERT_DIR, 'server.crt')
KEY_FILE   = os.path.join(CERT_DIR, 'server.key')

def generate():
    os.makedirs(CERT_DIR, exist_ok=True)

    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print(f"Certificates already exist")
        print(f"Delete them and re-run to regenerate.")
        return

    print("Generating self-signed RSA-2048 TLS certificate ...")

    cmd = [
        'openssl', 'req',
        '-x509',
        '-newkey', 'rsa:2048',
        '-keyout', KEY_FILE,
        '-out',    CERT_FILE,
        '-days',   '365',
        '-nodes',
        '-subj',   '/CN=localhost/O=CloudSec-Lab/C=US',
        '-addext', 'subjectAltName=IP:127.0.0.1,DNS:localhost',
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR running openssl:\n{result.stderr}")
        sys.exit(1)

    print(f"Certificate and Private key generated successfully!")

generate()
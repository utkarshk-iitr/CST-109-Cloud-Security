import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

STORAGE_DIR = os.path.join(BASE_DIR, "storage_nodes")
SECURITY_DIR = os.path.join(BASE_DIR, "security")
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(SECURITY_DIR, exist_ok=True)

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8081
IAM_HOST = "127.0.0.1"
IAM_PORT = 5001

BACKEND_SERVERS = [
    {"id": "backend_1", "host": "127.0.0.1", "port": 7001},
    {"id": "backend_2", "host": "127.0.0.1", "port": 7002},
]

TLS_CERT_FILE = os.path.join(ROOT_DIR, "certs", "server.crt")
TLS_KEY_FILE = os.path.join(ROOT_DIR, "certs", "server.key")
KEY_RING_FILE = os.path.join(SECURITY_DIR, "keyring.json")
KEY_RING_RETAIN = 6
KEY_SEC = 300

JWT_SECRET = "abra_cadabra_gili_gili_chhoo"
JWT_EXP = 180
REFRESH_EXP = 1800
RENEW_TIME = 120
MAX_LOGIN_ATTEMPTS = 5
LOCK_SEC = 300
REQ_MIN = 60
INV_THRESHOLD = 5
UNAUTH_THRESHOLD = 3
UNUSUAL_ACCESS = 20

import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8081

IAM_HOST = "127.0.0.1"
IAM_PORT = 5001

BACKEND_SERVERS = [
    {"id": "backend_1", "host": "127.0.0.1", "port": 7001},
    {"id": "backend_2", "host": "127.0.0.1", "port": 7002},
]

JWT_SECRET = "abra_cadabra_gili_gili_chhoo"
JWT_EXP_SECONDS = 180

MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCK_SECONDS = 300

MAX_REQ_PER_MIN = 60
INVALID_TOKEN_THRESHOLD = 5
BLOCK_IP_SECONDS = 300

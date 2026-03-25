import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 8081

IAM_HOST = "127.0.0.1"
IAM_PORT = 5001

BACKEND_SERVERS = [
    {"id": "backend_1", "host": "127.0.0.1", "port": 7001},
    {"id": "backend_2", "host": "127.0.0.1", "port": 7002},
]

JWT_SECRET = "lab4-super-secret-change-me"
JWT_EXP_SECONDS = 180

MAX_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCK_SECONDS = 300

MAX_REQ_PER_MIN = 60
INVALID_TOKEN_THRESHOLD = 5
BLOCK_IP_SECONDS = 300

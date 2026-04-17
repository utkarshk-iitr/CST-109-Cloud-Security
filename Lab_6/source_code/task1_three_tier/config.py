import os

WEB_HOST = os.getenv("WEB_HOST", "127.0.0.1")
WEB_PORT = int(os.getenv("WEB_PORT", "8080"))
WEB_TLS_CERT = os.getenv("WEB_TLS_CERT", "")
WEB_TLS_KEY = os.getenv("WEB_TLS_KEY", "")

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "cloud_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "cloud_pass_123")
DB_NAME = os.getenv("DB_NAME", "cloud_security")

WEB_ALLOWED_ORIGIN = os.getenv("WEB_ALLOWED_ORIGIN", "*")

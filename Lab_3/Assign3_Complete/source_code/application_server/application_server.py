import socket
import json
import threading
import logging
import hashlib
import time
import os
from datetime import datetime, timedelta
from collections import defaultdict
import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

STORAGE_SERVERS = [
    {'host': '127.0.0.1', 'port': 6001, 'id': 'storage_1'},
    {'host': '127.0.0.1', 'port': 6002, 'id': 'storage_2'},
    {'host': '127.0.0.1', 'port': 6003, 'id': 'storage_3'},
    {'host': '127.0.0.1', 'port': 6004, 'id': 'storage_4'},
]
APPLICATION_SERVER_HOST = '127.0.0.1'
APPLICATION_SERVER_PORT = 5000

MAX_REQUESTS_PER_MINUTE = 60
MAX_FAILED_AUTH = 5
LOCKOUT_DURATION = 300
TOKEN_EXPIRY = 3600*24

ROLE_ADMIN = 'admin'
ROLE_USER = 'user'
ROLE_READONLY = 'readonly'

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'application_server.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ApplicationServer')

security_logger = logging.getLogger('SecurityMonitor')
security_handler = logging.FileHandler(os.path.join(LOG_DIR, 'auth.log'))
security_handler.setFormatter(logging.Formatter(LOG_FORMAT))
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.INFO)

threat_logger = logging.getLogger('ThreatDetection')
threat_handler = logging.FileHandler(os.path.join(LOG_DIR, 'threats.log'))
threat_handler.setFormatter(logging.Formatter(LOG_FORMAT))
threat_logger.addHandler(threat_handler)
threat_logger.setLevel(logging.WARNING)


class SecurityMonitor:
    def __init__(self):
        self.request_history = defaultdict(list)
        self.failed_auth = defaultdict(int)
        self.locked_ips = {}
        self.blocked_ips = set()
        self.lock = threading.Lock()
    
    def check_rate_limit(self, client_ip):
        with self.lock:
            now = time.time()
            self.request_history[client_ip] = [
                ts for ts in self.request_history[client_ip] 
                if now - ts < 60
            ]
            
            if len(self.request_history[client_ip]) >= MAX_REQUESTS_PER_MINUTE:
                threat_logger.warning(f"Rate limit exceeded for {client_ip}")
                return False
            
            self.request_history[client_ip].append(now)
            return True
    
    def record_failed_auth(self, client_ip):
        with self.lock:
            self.failed_auth[client_ip] += 1
            security_logger.warning(f"Failed authentication from {client_ip} (count: {self.failed_auth[client_ip]})")
            
            if self.failed_auth[client_ip] >= MAX_FAILED_AUTH:
                lockout_until = time.time() + LOCKOUT_DURATION
                self.locked_ips[client_ip] = lockout_until
                threat_logger.critical(f"IP {client_ip} locked out due to {MAX_FAILED_AUTH} failed auth attempts")
                return True
            return False
    
    def is_locked_out(self, client_ip):
        with self.lock:
            if client_ip in self.locked_ips:
                if time.time() < self.locked_ips[client_ip]:
                    return True
                else:
                    del self.locked_ips[client_ip]
                    self.failed_auth[client_ip] = 0
            return False
    
    def is_blocked(self, client_ip):
        return client_ip in self.blocked_ips
    
    def block_ip(self, client_ip):
        with self.lock:
            self.blocked_ips.add(client_ip)
            threat_logger.critical(f"IP {client_ip} permanently blocked")
    
    def reset_failed_auth(self, client_ip):
        with self.lock:
            if client_ip in self.failed_auth:
                self.failed_auth[client_ip] = 0


class AuthenticationManager:
    def __init__(self):
        self.tokens = {}
        self.users = {
            'admin': {'password_hash': self._hash_password('admin123'), 'role': ROLE_ADMIN},
            'user1': {'password_hash': self._hash_password('user123'), 'role': ROLE_USER},
            'readonly': {'password_hash': self._hash_password('read123'), 'role': ROLE_READONLY}
        }
        self.lock = threading.Lock()
    
    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate(self, username, password, client_ip):
        if username not in self.users:
            security_logger.warning(f"Authentication failed: Unknown user '{username}' from {client_ip}")
            return None
        
        password_hash = self._hash_password(password)
        if self.users[username]['password_hash'] != password_hash:
            security_logger.warning(f"Authentication failed: Invalid password for '{username}' from {client_ip}")
            return None
        
        token = secrets.token_urlsafe(32)
        expires = datetime.now() + timedelta(seconds=TOKEN_EXPIRY)
        
        with self.lock:
            self.tokens[token] = {'user': username,'role': self.users[username]['role'],'expires': expires,'ip': client_ip}
        
        security_logger.info(f"Successful authentication: user '{username}' from {client_ip}")
        return token
    
    def validate_token(self, token, client_ip):
        with self.lock:
            if token not in self.tokens:
                security_logger.warning(f"Invalid token from {client_ip}")
                return None
            
            token_data = self.tokens[token]
            if datetime.now() > token_data['expires']:
                security_logger.warning(f"Expired token from {client_ip}")
                del self.tokens[token]
                return None
            if token_data['ip'] != client_ip:
                security_logger.warning(f"Token IP mismatch: expected {token_data['ip']}, got {client_ip}")
                return None
            
            return token_data
    
    def revoke_token(self, token):
        with self.lock:
            if token in self.tokens:
                del self.tokens[token]


class ApplicationServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.files = {}
        self.storage_servers = STORAGE_SERVERS.copy()
        self.index = 0
        self.lock = threading.Lock()
        
        self.security_monitor = SecurityMonitor()
        self.auth_manager = AuthenticationManager()
        
    def get_server(self):
        with self.lock:
            server = self.storage_servers[self.index]
            self.index = (self.index + 1) % len(self.storage_servers)
            return server
    
    def check_permission(self, operation, role):
        permissions = {
            'LOGIN': [ROLE_ADMIN, ROLE_USER, ROLE_READONLY],
            'UPLOAD_REQUEST': [ROLE_ADMIN, ROLE_USER],
            'UPLOAD_COMPLETE': [ROLE_ADMIN, ROLE_USER],
            'DOWNLOAD_REQUEST': [ROLE_ADMIN, ROLE_USER, ROLE_READONLY],
            'LIST_FILES': [ROLE_ADMIN, ROLE_USER, ROLE_READONLY],
            'DELETE_FILE': [ROLE_ADMIN],
        }
        
        return role in permissions.get(operation, [])
    
    def handle_client(self, client_socket, address):
        client_ip = address[0]
        
        try:
            if self.security_monitor.is_blocked(client_ip):
                logger.warning(f"Blocked IP attempted connection: {client_ip}")
                error_response = {'status': 'ERROR', 'message': 'IP blocked'}
                client_socket.send(json.dumps(error_response).encode())
                return
            
            if self.security_monitor.is_locked_out(client_ip):
                logger.warning(f"Locked out IP attempted connection: {client_ip}")
                error_response = {'status': 'ERROR', 'message': 'Account locked. Try again later.'}
                client_socket.send(json.dumps(error_response).encode())
                return
            
            if not self.security_monitor.check_rate_limit(client_ip):
                logger.warning(f"Rate limit exceeded: {client_ip}")
                error_response = {'status': 'ERROR', 'message': 'Rate limit exceeded'}
                client_socket.send(json.dumps(error_response).encode())
                return
            
            data = client_socket.recv(4096).decode()
            request = json.loads(data)
            operation = request.get('operation')
            logger.info(f"Request from {client_ip}: {operation}")
            
            if operation == 'LOGIN':
                response = self.handle_login(request, client_ip)
            else:
                token = request.get('token')
                if not token:
                    security_logger.warning(f"Missing token from {client_ip}")
                    response = {'status': 'ERROR', 'message': 'Authentication required'}
                else:
                    token_data = self.auth_manager.validate_token(token, client_ip)
                    if not token_data:
                        response = {'status': 'ERROR', 'message': 'Invalid or expired token'}
                    elif not self.check_permission(operation, token_data['role']):
                        security_logger.warning(f"Unauthorized access attempt: {token_data['user']} tried {operation}")
                        response = {'status': 'ERROR', 'message': 'Permission denied'}
                    else:
                        response = self.handle_authorized_request(request, token_data)
            
            client_socket.send(json.dumps(response).encode())
            
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from {client_ip}")
            error_response = {'status': 'ERROR', 'message': 'Invalid request format'}
            client_socket.send(json.dumps(error_response).encode())
        except Exception as e:
            logger.error(f"Error handling client {client_ip}: {e}")
            error_response = {'status': 'ERROR', 'message': str(e)}
            client_socket.send(json.dumps(error_response).encode())
        finally:
            client_socket.close()
    
    def handle_login(self, request, client_ip):
        username = request.get('username')
        password = request.get('password')
        
        if not username or not password:
            return {'status': 'ERROR', 'message': 'Username and password required'}
        
        token = self.auth_manager.authenticate(username, password, client_ip)
        
        if token:
            self.security_monitor.reset_failed_auth(client_ip)
            return {'status': 'SUCCESS', 'token': token, 'message': 'Login successful'}
        else:
            locked = self.security_monitor.record_failed_auth(client_ip)
            if locked:
                return {'status': 'ERROR', 'message': f'Account locked for {LOCKOUT_DURATION} seconds'}
            return {'status': 'ERROR', 'message': 'Invalid credentials'}
    
    def handle_authorized_request(self, request, token_data):
        operation = request['operation']
        user = token_data['user']
        
        logger.info(f"Authorized request: {operation} by user '{user}'")
        
        if operation == 'UPLOAD_REQUEST':
            return self.handle_upload(request, user)
        elif operation == 'DOWNLOAD_REQUEST':
            return self.handle_download(request, user)
        elif operation == 'LIST_FILES':
            return self.list_files(user)
        elif operation == 'UPLOAD_COMPLETE':
            return self.handle_complete(request, user)
        elif operation == 'DELETE_FILE':
            return self.handle_delete(request, user)
        else:
            return {'status': 'ERROR', 'message': 'Unknown operation'}
    
    def handle_upload(self, request, user):
        filename = request['filename']
        file_size = request['file_size']
        n = request['num_chunks']
        
        logger.info(f"Upload request by {user}: {filename} ({file_size} bytes, {n} chunks)")
        
        alloc = []
        for chunk_id in range(n):
            server = self.get_server()
            alloc.append({'chunk_id': chunk_id, 'server': server})
            logger.info(f"  Chunk {chunk_id} -> {server['id']}")
        
        return {'status': 'SUCCESS', 'chunk_allocations': alloc}
    
    def handle_complete(self, request, user):
        filename = request['filename']
        chunks = request['chunks']
        total_size = request['total_size']
        
        with self.lock:
            self.files[filename] = {'chunks': chunks,'total_size': total_size,'upload_time': datetime.now().isoformat(),'uploaded_by': user}
        
        logger.info(f"Upload complete by {user}: {filename} - {len(chunks)} chunks, {total_size} bytes")
        return {'status': 'SUCCESS', 'message': 'File registered successfully'}
    
    def handle_download(self, request, user):
        filename = request['filename']
        
        # IDOR / Path traversal check
        if '..' in filename or '/' in filename or '\\' in filename:
            security_logger.warning(f"IDOR/Path traversal attempt by {user}: {filename}")
            threat_logger.warning(f"THREAT: IDOR/Path traversal attempt | User: {user} | File: {filename}")
            return {'status': 'ERROR', 'message': 'Invalid filename'}
        
        with self.lock:
            if filename not in self.files:
                logger.warning(f"Download request by {user} for non-existent file: {filename}")
                return {'status': 'ERROR', 'message': 'File not found'}
            file_info = self.files[filename]
        
        logger.info(f"Download request by {user}: {filename} - {len(file_info['chunks'])} chunks")
        return {'status': 'SUCCESS','chunks': file_info['chunks'],'total_size': file_info['total_size']}
    
    def list_files(self, user):
        with self.lock:
            file_list = []
            for filename, info in self.files.items():
                file_list.append({'filename': filename,'size': info['total_size'],'chunks': len(info['chunks']),'upload_time': info['upload_time'],'uploaded_by': info.get('uploaded_by', 'unknown')})
        
        logger.info(f"List files request by {user} - {len(file_list)} files")
        return {'status': 'SUCCESS', 'files': file_list}
    
    def handle_delete(self, request, user):
        filename = request['filename']
        
        with self.lock:
            if filename not in self.files:
                return {'status': 'ERROR', 'message': 'File not found'}
            del self.files[filename]
        
        logger.info(f"File deleted by {user}: {filename}")
        return {'status': 'SUCCESS', 'message': 'File deleted successfully'}
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        logger.info(f"Application Server started on {self.host}:{self.port}")
        logger.info(f"Managing {len(self.storage_servers)} storage servers")
        logger.info("Security features: Authentication, Authorization, Rate Limiting, Account Lockout")
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client,args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logger.info("Application Server shutting down...")
        finally:
            server_socket.close()


server = ApplicationServer(APPLICATION_SERVER_HOST, APPLICATION_SERVER_PORT)
server.start()

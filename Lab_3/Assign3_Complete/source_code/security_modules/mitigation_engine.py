import time
import threading
import logging
from collections import defaultdict

RATE_LIMIT_PER_MIN = 30
BRUTE_FORCE_THRESHOLD = 5
LOCKOUT_DURATION = 300     
DOS_THRESHOLD = 100
AUTO_BLOCK_DURATION = 600    
MAX_CHUNK_SIZE = 10 * 1024 * 1024 
TOKEN_EXPIRY = 86400        

class MitigationEngine:
    def __init__(self, logger=None):
        self.request_counts = defaultdict(list)
        self.failed_auths = defaultdict(int)
        self.locked_accounts = {}
        self.blocked_ips = {}
        self.lock = threading.Lock()
        self.log = logger or logging.getLogger('MitigationEngine')

        self.stats = {'total_blocks': 0, 'total_rate_limits': 0, 'total_lockouts': 0}

    def check_request(self, client_ip):
        with self.lock:
            if client_ip in self.blocked_ips:
                unblock = self.blocked_ips[client_ip]
                if unblock == 0 or time.time() < unblock:
                    return False, "IP blocked"
                else:
                    del self.blocked_ips[client_ip]

            if client_ip in self.locked_accounts:
                if time.time() < self.locked_accounts[client_ip]:
                    return False, "Account locked"
                else:
                    del self.locked_accounts[client_ip]
                    self.failed_auths[client_ip] = 0

            now = time.time()
            self.request_counts[client_ip] = [
                ts for ts in self.request_counts[client_ip] if now - ts < 60
            ]
            count = len(self.request_counts[client_ip])

            if count >= DOS_THRESHOLD:
                self.blocked_ips[client_ip] = now + AUTO_BLOCK_DURATION
                self.stats['total_blocks'] += 1
                self.log.critical(f"AUTO-BLOCK: {client_ip} (DoS: {count} req/min)")
                return False, "IP blocked - DoS detected"

            if count >= RATE_LIMIT_PER_MIN:
                self.stats['total_rate_limits'] += 1
                self.log.warning(f"RATE-LIMIT: {client_ip} ({count} req/min)")
                return False, "Rate limit exceeded"

            self.request_counts[client_ip].append(now)
        return True, "OK"

    def record_auth_failure(self, client_ip):
        with self.lock:
            self.failed_auths[client_ip] += 1
            count = self.failed_auths[client_ip]
            if count >= BRUTE_FORCE_THRESHOLD:
                self.locked_accounts[client_ip] = time.time() + LOCKOUT_DURATION
                self.stats['total_lockouts'] += 1
                self.log.critical(f"LOCKOUT: {client_ip} ({count} failed attempts)")
                return True
        return False

    def record_auth_success(self, client_ip):
        with self.lock:
            self.failed_auths[client_ip] = 0

    def get_status(self):
        with self.lock:
            return {
                'blocked_ips': list(self.blocked_ips.keys()),
                'locked_accounts': list(self.locked_accounts.keys()),
                'stats': dict(self.stats),
            }


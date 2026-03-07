"""
Automated Risk Mitigation Engine.
Defines and displays all mitigation rules used by the system.
Can be imported by other modules or run standalone to view rules.
"""

import time
import threading
import logging
from datetime import datetime
from collections import defaultdict

# ================== Mitigation Thresholds ==================
RATE_LIMIT_PER_MIN = 30
BRUTE_FORCE_THRESHOLD = 5
LOCKOUT_DURATION = 300       # seconds
DOS_THRESHOLD = 100
AUTO_BLOCK_DURATION = 600    # seconds
MAX_CHUNK_SIZE = 10 * 1024 * 1024  # 10 MB
TOKEN_EXPIRY = 86400         # 24 hours


class MitigationEngine:
    """Automated mitigation engine - provides rate limiting, IP blocking, account lockout."""

    def __init__(self, logger=None):
        self.request_counts = defaultdict(list)
        self.failed_auths = defaultdict(int)
        self.locked_accounts = {}
        self.blocked_ips = {}
        self.lock = threading.Lock()
        self.log = logger or logging.getLogger('MitigationEngine')

        self.stats = {
            'total_blocks': 0,
            'total_rate_limits': 0,
            'total_lockouts': 0,
        }

    def check_request(self, client_ip):
        """Check if a request should be allowed. Returns (allowed, reason)."""
        with self.lock:
            # Check IP block
            if client_ip in self.blocked_ips:
                unblock = self.blocked_ips[client_ip]
                if unblock == 0 or time.time() < unblock:
                    return False, "IP blocked"
                else:
                    del self.blocked_ips[client_ip]

            # Check account lockout
            if client_ip in self.locked_accounts:
                if time.time() < self.locked_accounts[client_ip]:
                    return False, "Account locked"
                else:
                    del self.locked_accounts[client_ip]
                    self.failed_auths[client_ip] = 0

            # Rate limit check
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
        """Record a failed login. Returns True if account is now locked."""
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
        """Reset failed auth counter on successful login."""
        with self.lock:
            self.failed_auths[client_ip] = 0

    def get_status(self):
        """Return current mitigation engine status."""
        with self.lock:
            return {
                'blocked_ips': list(self.blocked_ips.keys()),
                'locked_accounts': list(self.locked_accounts.keys()),
                'stats': dict(self.stats),
            }


# ================== Mitigation Rules Display ==================

MITIGATION_RULES = [
    {
        'id': 'M1',
        'name': 'Rate Limiting',
        'trigger': f'{RATE_LIMIT_PER_MIN} requests per minute from a single IP',
        'action': 'Reject all subsequent requests until the 60-second window resets',
        'automated': True,
        'component': 'API Gateway',
    },
    {
        'id': 'M2',
        'name': 'Account Lockout (Brute-Force Protection)',
        'trigger': f'{BRUTE_FORCE_THRESHOLD} consecutive failed login attempts from an IP',
        'action': f'Lock out the IP for {LOCKOUT_DURATION} seconds, reject all login attempts',
        'automated': True,
        'component': 'API Gateway + Application Server',
    },
    {
        'id': 'M3',
        'name': 'IP Auto-Blocking (DoS Protection)',
        'trigger': f'{DOS_THRESHOLD} requests per minute from a single IP (DoS pattern)',
        'action': f'Automatically block the IP for {AUTO_BLOCK_DURATION} seconds',
        'automated': True,
        'component': 'API Gateway',
    },
    {
        'id': 'M4',
        'name': 'Token Validation & Expiration',
        'trigger': 'Invalid, expired, or IP-mismatched authentication token',
        'action': 'Reject request, log unauthorized access attempt',
        'automated': True,
        'component': 'Application Server',
    },
    {
        'id': 'M5',
        'name': 'Role-Based Access Control',
        'trigger': 'User attempts an operation not allowed for their role',
        'action': 'Reject request with "Permission denied", log the attempt',
        'automated': True,
        'component': 'Application Server',
    },
    {
        'id': 'M6',
        'name': 'Data Integrity Verification',
        'trigger': 'SHA-256 checksum mismatch when retrieving a file chunk',
        'action': 'Reject the data, return error, log integrity violation',
        'automated': True,
        'component': 'Storage Servers',
    },
    {
        'id': 'M7',
        'name': 'Chunk Size Limit',
        'trigger': f'Upload chunk exceeds {MAX_CHUNK_SIZE // (1024*1024)} MB limit',
        'action': 'Reject the upload request',
        'automated': True,
        'component': 'Storage Servers',
    },
    {
        'id': 'M8',
        'name': 'Comprehensive Audit Logging',
        'trigger': 'All security-relevant events (auth, access, threats)',
        'action': 'Log to auth.log, threats.log, mitigation.log with timestamps',
        'automated': True,
        'component': 'All Components',
    },
]


def display_rules():
    """Display all automated mitigation rules."""
    print("=" * 70)
    print("  AUTOMATED RISK MITIGATION RULES")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    for rule in MITIGATION_RULES:
        auto = "AUTOMATED" if rule['automated'] else "MANUAL"
        print(f"\n  Rule {rule['id']}: {rule['name']} [{auto}]")
        print(f"    Component: {rule['component']}")
        print(f"    Trigger:   {rule['trigger']}")
        print(f"    Action:    {rule['action']}")

    print(f"\n{'='*70}")
    print(f"  Total rules: {len(MITIGATION_RULES)}")
    automated = sum(1 for r in MITIGATION_RULES if r['automated'])
    print(f"  Automated:   {automated}/{len(MITIGATION_RULES)}")
    print(f"{'='*70}\n")


if __name__ == '__main__':
    display_rules()

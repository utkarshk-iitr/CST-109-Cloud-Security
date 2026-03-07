"""
Automated Threat Modeler using STRIDE Methodology.
Analyzes system architecture and log files to identify and assess threats.
Can be run standalone to generate a threat model report.
"""

import os
import re
from datetime import datetime
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, 'logs')

# ================== STRIDE Categories ==================
STRIDE = {
    'S': 'Spoofing        - Impersonating something or someone else',
    'T': 'Tampering       - Modifying data or code without authorization',
    'R': 'Repudiation     - Denying having performed an action',
    'I': 'Info Disclosure - Exposing data to unauthorized parties',
    'D': 'Denial of Svc   - Degrading or denying service to users',
    'E': 'Elev. Privilege - Gaining capabilities without authorization',
}

# ================== Architecture Model ==================
COMPONENTS = [
    {'name': 'Client',              'trust': 'Untrusted', 'exposed': True},
    {'name': 'API Gateway',         'trust': 'Boundary',  'exposed': True},
    {'name': 'Application Server',  'trust': 'Trusted',   'exposed': False},
    {'name': 'Storage Servers',     'trust': 'Trusted',   'exposed': False},
    {'name': 'Log Storage',         'trust': 'Trusted',   'exposed': False},
]

DATA_FLOWS = [
    {'from': 'Client',             'to': 'API Gateway',         'data': 'Login/file requests',  'boundary': True},
    {'from': 'API Gateway',        'to': 'Application Server',  'data': 'Forwarded requests',   'boundary': True},
    {'from': 'Application Server', 'to': 'Storage Servers',     'data': 'Chunk allocations',    'boundary': False},
    {'from': 'Client',             'to': 'Storage Servers',     'data': 'File chunk data',      'boundary': True},
    {'from': 'All Components',     'to': 'Log Storage',         'data': 'Audit/security logs',  'boundary': False},
]

# ================== Threat Definitions ==================
THREATS = [
    {
        'id': 'T1', 'category': 'S',
        'name': 'Credential Stuffing / Brute Force',
        'description': 'Attacker tries many username/password combinations to gain access.',
        'target': 'API Gateway / Application Server',
        'severity': 'HIGH', 'likelihood': 'HIGH',
        'mitigation': 'Account lockout after 5 failed attempts, rate limiting at gateway',
        'implemented': True,
    },
    {
        'id': 'T2', 'category': 'S',
        'name': 'Token Theft / Replay',
        'description': 'Attacker steals or replays a valid authentication token.',
        'target': 'Application Server',
        'severity': 'HIGH', 'likelihood': 'MEDIUM',
        'mitigation': 'Token bound to client IP, token expiration (24h), secure random generation',
        'implemented': True,
    },
    {
        'id': 'T3', 'category': 'T',
        'name': 'Data Tampering in Storage',
        'description': 'Attacker or process modifies stored file chunks.',
        'target': 'Storage Servers',
        'severity': 'HIGH', 'likelihood': 'LOW',
        'mitigation': 'SHA-256 integrity checksums verified on every retrieval',
        'implemented': True,
    },
    {
        'id': 'T4', 'category': 'T',
        'name': 'Request Tampering in Transit',
        'description': 'Attacker modifies requests between client and server.',
        'target': 'Data Flow (Client -> Gateway)',
        'severity': 'MEDIUM', 'likelihood': 'MEDIUM',
        'mitigation': 'JSON schema validation, server-side authorization checks',
        'implemented': True,
    },
    {
        'id': 'T5', 'category': 'R',
        'name': 'Action Denial',
        'description': 'User denies having uploaded, deleted, or accessed files.',
        'target': 'Application Server',
        'severity': 'LOW', 'likelihood': 'MEDIUM',
        'mitigation': 'Comprehensive audit logging with timestamps, IPs, and usernames',
        'implemented': True,
    },
    {
        'id': 'T6', 'category': 'I',
        'name': 'Unauthorized File Access',
        'description': 'User accesses files beyond their role permissions.',
        'target': 'Application Server',
        'severity': 'HIGH', 'likelihood': 'MEDIUM',
        'mitigation': 'Role-based access control (admin/user/readonly) enforced server-side',
        'implemented': True,
    },
    {
        'id': 'T7', 'category': 'I',
        'name': 'Log Information Leakage',
        'description': 'Sensitive data exposed through log files.',
        'target': 'Log Storage',
        'severity': 'MEDIUM', 'likelihood': 'LOW',
        'mitigation': 'Passwords never logged, tokens truncated in logs',
        'implemented': True,
    },
    {
        'id': 'T8', 'category': 'D',
        'name': 'Denial of Service (Request Flood)',
        'description': 'Attacker sends high volume of requests to overwhelm the system.',
        'target': 'API Gateway',
        'severity': 'HIGH', 'likelihood': 'HIGH',
        'mitigation': 'Rate limiting (30/min), auto IP blocking at 100 req/min threshold',
        'implemented': True,
    },
    {
        'id': 'T9', 'category': 'D',
        'name': 'Service Exhaustion',
        'description': 'Attacker exhausts storage or connection resources.',
        'target': 'Storage Servers',
        'severity': 'MEDIUM', 'likelihood': 'LOW',
        'mitigation': 'Max chunk size limit (10MB), rate limiting per storage server',
        'implemented': True,
    },
    {
        'id': 'T10', 'category': 'E',
        'name': 'Privilege Escalation',
        'description': 'Regular user attempts admin-only operations (e.g., delete).',
        'target': 'Application Server',
        'severity': 'CRITICAL', 'likelihood': 'MEDIUM',
        'mitigation': 'Server-side role checking, token contains role from server DB only',
        'implemented': True,
    },
    {
        'id': 'T11', 'category': 'S',
        'name': 'Invalid / Tampered Token',
        'description': 'Attacker sends a fabricated, modified, or malformed token to bypass authentication.',
        'target': 'Application Server',
        'severity': 'HIGH', 'likelihood': 'HIGH',
        'mitigation': 'Server-side token lookup (not decoded from client), invalid tokens rejected and logged',
        'implemented': True,
    },
    {
        'id': 'T12', 'category': 'S',
        'name': 'Replay Attack',
        'description': 'Attacker captures and reuses a valid token from a previous session.',
        'target': 'Application Server',
        'severity': 'HIGH', 'likelihood': 'MEDIUM',
        'mitigation': 'Token bound to client IP, token expiration (24h), unique cryptographic token IDs',
        'implemented': True,
    },
    {
        'id': 'T13', 'category': 'E',
        'name': 'Insecure Direct Object Reference (IDOR)',
        'description': 'Attacker manipulates object identifiers (filenames, paths) to access unauthorized resources.',
        'target': 'Application Server',
        'severity': 'HIGH', 'likelihood': 'MEDIUM',
        'mitigation': 'Path traversal blocked, RBAC enforced, server-side authorization on every request',
        'implemented': True,
    },
]

RISK_MATRIX = {'CRITICAL': 10, 'HIGH': 8, 'MEDIUM': 5, 'LOW': 2}
LIKELIHOOD_WEIGHT = {'HIGH': 1.0, 'MEDIUM': 0.6, 'LOW': 0.3}


def analyze_architecture():
    """Print the STRIDE threat model report for the architecture."""
    print("=" * 70)
    print("  AUTOMATED THREAT MODEL REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Methodology: STRIDE")
    print("=" * 70)

    # 1. Components
    print("\n  1. SYSTEM COMPONENTS")
    print("  " + "-" * 50)
    print(f"  {'Component':<25} {'Trust Level':<12} {'Internet-Facing'}")
    print("  " + "-" * 50)
    for c in COMPONENTS:
        exposed = "Yes" if c['exposed'] else "No"
        print(f"  {c['name']:<25} {c['trust']:<12} {exposed}")

    # 2. Data Flows
    print(f"\n  2. DATA FLOWS & TRUST BOUNDARIES")
    print("  " + "-" * 50)
    for flow in DATA_FLOWS:
        boundary = " [TRUST BOUNDARY]" if flow['boundary'] else ""
        print(f"  {flow['from']} -> {flow['to']}{boundary}")
        print(f"    Data: {flow['data']}")

    # 3. Trust Boundaries
    print(f"\n  3. TRUST BOUNDARIES")
    print("  " + "-" * 50)
    print("  B1: Internet <-> API Gateway        (untrusted -> boundary)")
    print("  B2: API Gateway <-> App Server       (boundary -> trusted)")
    print("  B3: Client <-> Storage Servers       (untrusted -> trusted)")

    # 4. STRIDE Analysis
    print(f"\n  4. STRIDE THREAT ANALYSIS")
    print("  " + "-" * 50)

    by_category = defaultdict(list)
    for t in THREATS:
        by_category[t['category']].append(t)

    total_risk = 0
    for key, desc in STRIDE.items():
        threats = by_category.get(key, [])
        print(f"\n  [{key}] {desc}")
        if not threats:
            print("      No threats identified")
            continue
        for t in threats:
            risk = RISK_MATRIX[t['severity']] * LIKELIHOOD_WEIGHT[t['likelihood']]
            total_risk += risk
            impl = "YES" if t['implemented'] else "NO"
            print(f"    {t['id']}: {t['name']}")
            print(f"        Severity: {t['severity']} | Likelihood: {t['likelihood']} | Risk Score: {risk:.1f}")
            print(f"        Target: {t['target']}")
            print(f"        Mitigation: {t['mitigation']}")
            print(f"        Implemented: {impl}")

    # 5. Risk Summary
    print(f"\n  5. RISK SUMMARY")
    print("  " + "-" * 50)
    print(f"  Total threats:  {len(THREATS)}")
    print(f"  Total risk:     {total_risk:.1f}")
    print(f"  Avg risk/threat: {total_risk/len(THREATS):.1f}")

    sev_counts = defaultdict(int)
    for t in THREATS:
        sev_counts[t['severity']] += 1
    for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        print(f"    {s}: {sev_counts.get(s, 0)} threats")

    implemented = sum(1 for t in THREATS if t['implemented'])
    print(f"\n  Mitigations implemented: {implemented}/{len(THREATS)}")

    return total_risk


def analyze_logs():
    """Scan log files for evidence of actual threats."""
    print(f"\n\n{'='*70}")
    print("  LOG-BASED THREAT EVIDENCE ANALYSIS")
    print(f"{'='*70}")

    if not os.path.exists(LOG_DIR):
        print("\n  No logs directory found. Run the system first.")
        return {}

    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith('.log')]
    if not log_files:
        print("\n  No log files found. Run the system to generate logs.")
        return {}

    findings = {
        'auth_success': 0,
        'auth_failure': 0,
        'brute_force': 0,
        'rate_limit': 0,
        'ip_blocked': 0,
        'permission_denied': 0,
        'integrity_violation': 0,
        'dos_detected': 0,
    }

    for lf in log_files:
        filepath = os.path.join(LOG_DIR, lf)
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    ll = line.lower()
                    if 'auth success' in ll or 'successful authentication' in ll:
                        findings['auth_success'] += 1
                    if 'auth failed' in ll or 'authentication failed' in ll:
                        findings['auth_failure'] += 1
                    if 'brute' in ll:
                        findings['brute_force'] += 1
                    if 'rate limit' in ll:
                        findings['rate_limit'] += 1
                    if 'blocked' in ll or 'ip blocked' in ll:
                        findings['ip_blocked'] += 1
                    if 'permission denied' in ll or 'unauthorized' in ll:
                        findings['permission_denied'] += 1
                    if 'integrity' in ll:
                        findings['integrity_violation'] += 1
                    if 'dos' in ll:
                        findings['dos_detected'] += 1
        except Exception as e:
            print(f"  Error reading {lf}: {e}")

    print(f"\n  Log files analyzed: {len(log_files)}")
    print(f"\n  FINDINGS:")
    print(f"    Successful logins:       {findings['auth_success']}")
    print(f"    Failed logins:           {findings['auth_failure']}")
    print(f"    Brute-force detections:  {findings['brute_force']}")
    print(f"    Rate limit events:       {findings['rate_limit']}")
    print(f"    IP block events:         {findings['ip_blocked']}")
    print(f"    Permission denials:      {findings['permission_denied']}")
    print(f"    Integrity violations:    {findings['integrity_violation']}")
    print(f"    DoS detections:          {findings['dos_detected']}")

    # Active threat assessment
    active_threats = []
    if findings['brute_force'] > 0:
        active_threats.append(f"Brute-force attacks detected ({findings['brute_force']} events)")
    if findings['dos_detected'] > 0:
        active_threats.append(f"DoS attacks detected ({findings['dos_detected']} events)")
    if findings['rate_limit'] > 5:
        active_threats.append(f"High rate-limit activity ({findings['rate_limit']} events)")
    if findings['integrity_violation'] > 0:
        active_threats.append(f"Data integrity violations ({findings['integrity_violation']} events)")
    if findings['permission_denied'] > 3:
        active_threats.append(f"Multiple authorization failures ({findings['permission_denied']} events)")

    if active_threats:
        print(f"\n  ACTIVE THREATS:")
        for t in active_threats:
            print(f"    [!] {t}")
    else:
        print(f"\n  No active threats detected in logs.")

    return findings


if __name__ == '__main__':
    analyze_architecture()
    analyze_logs()
    print(f"\n{'='*70}")
    print("  Threat modeling report complete.")
    print(f"{'='*70}\n")

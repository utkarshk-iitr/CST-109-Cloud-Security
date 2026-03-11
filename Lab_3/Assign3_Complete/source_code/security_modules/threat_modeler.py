import os
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, 'logs')

STRIDE_NAMES = {'S': 'Spoofing', 'T': 'Tampering', 'R': 'Repudiation',
                'I': 'Information Disclosure', 'D': 'Denial of Service', 'E': 'Elevation of Privilege'}

THREATS = [
    ('T-01', 'S', 'Credential Spoofing via Stolen Tokens',                  4, 5),
    ('T-02', 'S', 'Identity Spoofing via Brute-Force Login',                5, 4),
    ('T-03', 'T', 'Chunk Data Tampering in Transit',                        2, 5),
    ('T-04', 'T', 'Request Payload Tampering (Path Traversal / IDOR)',      4, 5),
    ('T-05', 'R', 'Log Repudiation — Attacker Clears or Forges Logs',       2, 4),
    ('T-06', 'R', 'Action Repudiation — User Denies File Operations',       3, 3),
    ('T-07', 'I', 'Sensitive Data Exposure over Plaintext TCP',             4, 5),
    ('T-08', 'I', 'Token Store Exposure via In-Memory Leakage',             2, 4),
    ('T-09', 'D', 'Denial of Service via Request Flooding',                 5, 4),
    ('T-10', 'D', 'Storage Exhaustion via Large or Repeated Uploads',       3, 4),
    ('T-11', 'E', 'Privilege Escalation via Token Manipulation',            4, 5),
    ('T-12', 'E', 'Privilege Escalation via Unauthorized Operation Access', 4, 4),
]

RISK_MATRIX = {
    (1,1):'Very Low',(1,2):'Very Low',(1,3):'Low',   (1,4):'Low',   (1,5):'Medium',
    (2,1):'Very Low',(2,2):'Low',    (2,3):'Low',    (2,4):'Medium',(2,5):'Medium',
    (3,1):'Low',    (3,2):'Low',     (3,3):'Medium', (3,4):'Medium',(3,5):'High',
    (4,1):'Low',    (4,2):'Medium',  (4,3):'Medium', (4,4):'High',  (4,5):'Critical',
    (5,1):'Medium', (5,2):'Medium',  (5,3):'High',   (5,4):'High',  (5,5):'Critical',
}
RISK_ORDER = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Very Low': 0}


def analyze_logs():
    keys = ['auth_success', 'auth_failure', 'brute_force', 'rate_limit',
            'ip_blocked', 'permission_denied', 'integrity_violation', 'dos_detected']
    f = dict.fromkeys(keys, 0)
    if not os.path.exists(LOG_DIR):
        return f
    for lf in [x for x in os.listdir(LOG_DIR) if x.endswith('.log')]:
        try:
            for line in open(os.path.join(LOG_DIR, lf)):
                ll = line.lower()
                if 'auth success' in ll or 'successful authentication' in ll: f['auth_success'] += 1
                if 'auth failed' in ll or 'authentication failed' in ll:      f['auth_failure'] += 1
                if 'brute' in ll:                                              f['brute_force'] += 1
                if 'rate limit' in ll:                                         f['rate_limit'] += 1
                if 'blocked' in ll or 'ip blocked' in ll:                     f['ip_blocked'] += 1
                if 'permission denied' in ll or 'unauthorized' in ll:         f['permission_denied'] += 1
                if 'integrity' in ll:                                          f['integrity_violation'] += 1
                if 'dos' in ll:                                                f['dos_detected'] += 1
        except Exception:
            pass
    return f


def run_stride_analysis():
    print(f'\nSTRIDE Threat Model  |  {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    print('-' * 60)

    sorted_threats = sorted(THREATS, key=lambda t: RISK_ORDER.get(RISK_MATRIX.get((t[3], t[4]), ''), 0), reverse=True)
    dist = {}
    for tid, cat, title, l, i in sorted_threats:
        rl = RISK_MATRIX.get((l, i), 'Unknown')
        dist[rl] = dist.get(rl, 0) + 1
        print(f'  {tid}  [{cat}] {title:<45}  {rl} ({l*i}/25)')

    print('-' * 60)
    for level in ['Critical', 'High', 'Medium', 'Low', 'Very Low']:
        if dist.get(level):
            print(f'  {level:<12}: {dist[level]}')

    findings = analyze_logs()
    if any(findings.values()):
        print('\nLog Evidence:')
        labels = [('auth_failure', 'Auth failures'), ('brute_force', 'Brute-force'),
                  ('dos_detected', 'DoS detections'), ('ip_blocked', 'IP blocks'),
                  ('permission_denied', 'Authz denials'), ('integrity_violation', 'Integrity viol.')]
        for key, label in labels:
            if findings[key]:
                print(f'  {label:<16} : {findings[key]}')

    os.makedirs(LOG_DIR, exist_ok=True)
    report = {
        'generated': datetime.now().isoformat(),
        'methodology': 'STRIDE',
        'threats': [{'id': tid, 'stride': cat, 'category': STRIDE_NAMES[cat], 'title': title,
                     'likelihood': l, 'impact': i, 'risk_score': l*i,
                     'risk_level': RISK_MATRIX.get((l, i), 'Unknown')}
                    for tid, cat, title, l, i in sorted_threats],
        'risk_distribution': dist,
        'log_findings': findings,
    }
    with open(os.path.join(LOG_DIR, 'stride_threat_model.json'), 'w') as fp:
        json.dump(report, fp, indent=2)
    return report


run_stride_analysis()
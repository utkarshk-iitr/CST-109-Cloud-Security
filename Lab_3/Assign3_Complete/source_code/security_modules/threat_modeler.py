import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, 'logs')

def analyze_logs():
    print("\nLOG-BASED THREAT EVIDENCE ANALYSIS")

    if not os.path.exists(LOG_DIR):
        print("\nNo logs directory found. Run the system first.")
        return {}

    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith('.log')]
    if not log_files:
        print("\nNo log files found. Run the system to generate logs.")
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

    print(f"\nLog files analyzed: {len(log_files)}")
    print(f"\nFINDINGS:")
    print(f"- Successful logins:       {findings['auth_success']}")
    print(f"- Failed logins:           {findings['auth_failure']}")
    print(f"- Brute-force detections:  {findings['brute_force']}")
    print(f"- Rate limit events:       {findings['rate_limit']}")
    print(f"- IP block events:         {findings['ip_blocked']}")
    print(f"- Permission denials:      {findings['permission_denied']}")
    print(f"- Integrity violations:    {findings['integrity_violation']}")
    print(f"- DoS detections:          {findings['dos_detected']}")

    #active threat assessment
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
        print(f"\nACTIVE THREATS:")
        for i in range(len(active_threats)):
            print(f"{i + 1}. {active_threats[i]}")
    else:
        print(f"\nNo active threats detected in logs.")
    
    return findings

analyze_logs()

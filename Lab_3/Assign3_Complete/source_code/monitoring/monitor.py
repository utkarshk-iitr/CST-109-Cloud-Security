import os
import sys
import time
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, 'logs')

def read_all_events():
    auth_events = []
    threat_events = []
    miti_event = []
    all_events = []

    if not os.path.exists(LOG_DIR):
        return auth_events, threat_events, miti_event, all_events

    log_files = sorted([f for f in os.listdir(LOG_DIR) if f.endswith('.log')])

    for lf in log_files:
        filepath = os.path.join(LOG_DIR, lf)
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ll = line.lower()
                    all_events.append(line)

                    if any(kw in ll for kw in ['auth', 'login', 'authentication', 'credential']):
                        auth_events.append(line)
                    if any(kw in ll for kw in ['threat', 'attack', 'brute', 'dos', 'suspicious', 'violation']):
                        threat_events.append(line)
                    if any(kw in ll for kw in ['mitigation', 'blocked', 'lockout', 'rate limit', 'auto-block']):
                        miti_event.append(line)
        except Exception as e:
            pass

    return auth_events, threat_events, miti_event, all_events

def generate_report():
    print("-" * 21)
    print("SECURITY MONITORING REPORT")
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Log Directory: {LOG_DIR}")

    if not os.path.exists(LOG_DIR):
        print("\nNo logs directory found. Run the system first.")
        return

    log_files = sorted([f for f in os.listdir(LOG_DIR) if f.endswith('.log')])
    if not log_files:
        print("\nNo log files found. Start the servers and run some operations first.")
        return

    print(f"\nLOG FILES ({len(log_files)} files)")
    print("-" * 21)
    total_size = 0
    for lf in log_files:
        size = os.path.getsize(os.path.join(LOG_DIR, lf))
        total_size += size
        print(f"    {lf:<40} {size:>8} bytes")
    print(f"    {'TOTAL':<40} {total_size:>8} bytes")

    auth_events, threat_events, miti_event, all_events = read_all_events()

    print(f"\n{'-'*21}")
    print(f"AUTHENTICATION EVENTS ({len(auth_events)} total)")
    if auth_events:
        display = auth_events[-5:]
        for e in display:
            print(f"    {e}")
        if len(auth_events) > 5:
            print(f"    ... ({len(auth_events) - 5} earlier events not shown)")
    else:
        print("    No authentication events recorded.")

    print(f"\n{'-'*21}")
    print(f"THREAT DETECTION EVENTS ({len(threat_events)} total)")
    if threat_events:
        display = threat_events[-5:]
        for e in display:
            print(f"    {e}")
        if len(threat_events) > 5:
            print(f"    ... ({len(threat_events) - 5} earlier events not shown)")
    else:
        print("    No threat events recorded.")

    print(f"\n{'-'*21}")
    print(f"MITIGATION ACTIONS ({len(miti_event)} total)")
    if miti_event:
        display = miti_event[-5:]
        for e in display:
            print(f"    {e}")
        if len(miti_event) > 5:
            print(f"    ... ({len(miti_event) - 5} earlier events not shown)")
    else:
        print("    No mitigation events recorded.")

    print(f"\n{'-'*42}")
    print(f"SUMMARY")
    print(f"  Total log entries:        {len(all_events)}")
    print(f"  Authentication events:    {len(auth_events)}")
    print(f"  Threat detection events:  {len(threat_events)}")
    print(f"  Mitigation actions:       {len(miti_event)}")

    successes = sum(1 for e in auth_events if 'success' in e.lower())
    failures = sum(1 for e in auth_events if 'fail' in e.lower())
    blocks = sum(1 for e in miti_event if 'block' in e.lower())
    lockouts = sum(1 for e in miti_event if 'lockout' in e.lower() or 'locked' in e.lower())
    rate_limits = sum(1 for e in miti_event if 'rate limit' in e.lower())

    print(f"\n  Login successes:          {successes}")
    print(f"  Login failures:           {failures}")
    print(f"  IP blocks triggered:      {blocks}")
    print(f"  Account lockouts:         {lockouts}")
    print(f"  Rate limit enforcements:  {rate_limits}")

    if threat_events:
        print(f"\n  System Status: THREATS DETECTED - Review threat logs")
    else:
        print(f"\n  System Status: NORMAL - No active threats")

def live_monitor():
    print("-" * 21)
    print("LIVE SECURITY MONITOR")
    print(f"Watching: {LOG_DIR}")
    print("Press Ctrl+C to stop")

    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)
        print("Logs directory created. Waiting for log events...")

    positions = {}
    try:
        while True:
            if not os.path.exists(LOG_DIR):
                time.sleep(2)
                continue

            log_files = [f for f in os.listdir(LOG_DIR) if f.endswith('.log')]

            for lf in log_files:
                filepath = os.path.join(LOG_DIR, lf)

                if filepath not in positions:
                    try:
                        positions[filepath] = os.path.getsize(filepath)
                    except:
                        positions[filepath] = 0
                    continue
                try:
                    current_size = os.path.getsize(filepath)
                except:
                    continue

                if current_size > positions[filepath]:
                    try:
                        with open(filepath, 'r') as f:
                            f.seek(positions[filepath])
                            new_lines = f.readlines()
                            positions[filepath] = f.tell()
                    except:
                        continue

                    for line in new_lines:
                        line = line.strip()
                        if not line:
                            continue
                        ll = line.lower()

                        if 'critical' in ll or 'block' in ll or 'dos' in ll:
                            tag = "CRITICAL"
                        elif 'warning' in ll or 'threat' in ll or 'fail' in ll:
                            tag = "WARNING "
                        elif 'mitigation' in ll or 'lockout' in ll:
                            tag = "MITIGATE"
                        else:
                            tag = "INFO    "

                        print(f"  [{tag}] {line}")

            time.sleep(1)

    except KeyboardInterrupt:
        print("\nMonitor stopped.")

if len(sys.argv) > 1 and sys.argv[1] == '--live':
    live_monitor()
else:
    generate_report()

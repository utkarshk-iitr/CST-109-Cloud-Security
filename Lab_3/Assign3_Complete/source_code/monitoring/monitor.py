"""
Security Monitoring and Logging Module.
Reads log files and generates security reports.
Supports: static report mode and live monitoring mode.
"""

import os
import sys
import time
from datetime import datetime
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOG_DIR = os.path.join(BASE_DIR, 'logs')


def read_all_events():
    """Read all log events from LOG_DIR and categorize them."""
    auth_events = []
    threat_events = []
    mitigation_events = []
    all_events = []

    if not os.path.exists(LOG_DIR):
        return auth_events, threat_events, mitigation_events, all_events

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
                        mitigation_events.append(line)
        except Exception as e:
            pass

    return auth_events, threat_events, mitigation_events, all_events


def generate_report():
    """Generate a complete security monitoring report."""
    print("=" * 70)
    print("  SECURITY MONITORING REPORT")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Log Directory: {LOG_DIR}")
    print("=" * 70)

    if not os.path.exists(LOG_DIR):
        print("\n  No logs directory found. Run the system first.")
        return

    log_files = sorted([f for f in os.listdir(LOG_DIR) if f.endswith('.log')])
    if not log_files:
        print("\n  No log files found. Start the servers and run some operations first.")
        return

    print(f"\n  LOG FILES ({len(log_files)} files)")
    print("  " + "-" * 50)
    total_size = 0
    for lf in log_files:
        size = os.path.getsize(os.path.join(LOG_DIR, lf))
        total_size += size
        print(f"    {lf:<40} {size:>8} bytes")
    print(f"    {'TOTAL':<40} {total_size:>8} bytes")

    auth_events, threat_events, mitigation_events, all_events = read_all_events()

    # Authentication Events
    print(f"\n  {'='*70}")
    print(f"  AUTHENTICATION EVENTS ({len(auth_events)} total)")
    print(f"  {'='*70}")
    if auth_events:
        # Show last 15
        display = auth_events[-15:]
        for e in display:
            print(f"    {e}")
        if len(auth_events) > 15:
            print(f"    ... ({len(auth_events) - 15} earlier events not shown)")
    else:
        print("    No authentication events recorded.")

    # Threat Events
    print(f"\n  {'='*70}")
    print(f"  THREAT DETECTION EVENTS ({len(threat_events)} total)")
    print(f"  {'='*70}")
    if threat_events:
        display = threat_events[-15:]
        for e in display:
            print(f"    {e}")
        if len(threat_events) > 15:
            print(f"    ... ({len(threat_events) - 15} earlier events not shown)")
    else:
        print("    No threat events recorded.")

    # Mitigation Events
    print(f"\n  {'='*70}")
    print(f"  MITIGATION ACTIONS ({len(mitigation_events)} total)")
    print(f"  {'='*70}")
    if mitigation_events:
        display = mitigation_events[-15:]
        for e in display:
            print(f"    {e}")
        if len(mitigation_events) > 15:
            print(f"    ... ({len(mitigation_events) - 15} earlier events not shown)")
    else:
        print("    No mitigation events recorded.")

    # Summary Statistics
    print(f"\n  {'='*70}")
    print(f"  SUMMARY")
    print(f"  {'='*70}")
    print(f"    Total log entries:        {len(all_events)}")
    print(f"    Authentication events:    {len(auth_events)}")
    print(f"    Threat detection events:  {len(threat_events)}")
    print(f"    Mitigation actions:       {len(mitigation_events)}")

    # Count specific patterns
    successes = sum(1 for e in auth_events if 'success' in e.lower())
    failures = sum(1 for e in auth_events if 'fail' in e.lower())
    blocks = sum(1 for e in mitigation_events if 'block' in e.lower())
    lockouts = sum(1 for e in mitigation_events if 'lockout' in e.lower() or 'locked' in e.lower())
    rate_limits = sum(1 for e in mitigation_events if 'rate limit' in e.lower())

    print(f"\n    Login successes:          {successes}")
    print(f"    Login failures:           {failures}")
    print(f"    IP blocks triggered:      {blocks}")
    print(f"    Account lockouts:         {lockouts}")
    print(f"    Rate limit enforcements:  {rate_limits}")

    if threat_events:
        print(f"\n    System Status: THREATS DETECTED - Review threat logs")
    else:
        print(f"\n    System Status: NORMAL - No active threats")

    print(f"  {'='*70}\n")


def live_monitor():
    """Continuously watch log files for new events."""
    print("=" * 70)
    print("  LIVE SECURITY MONITOR")
    print(f"  Watching: {LOG_DIR}")
    print("  Press Ctrl+C to stop")
    print("=" * 70)

    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)
        print("  Logs directory created. Waiting for log events...")

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
                    # Start from current end of file
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

                        # Categorize and display
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
        print("\n  Monitor stopped.")


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--live':
        live_monitor()
    else:
        generate_report()
        print("  Tip: Run with --live for real-time monitoring")
        print("    python3 monitor.py --live\n")

#!/usr/bin/env bash
set -e

ALERT_FILE=${ALERT_FILE:-/var/log/snort/alert}
OUT_FILE=${OUT_FILE:-../../logs/ids.txt}

if [ ! -f "$ALERT_FILE" ]; then
  echo "alert file not found: $ALERT_FILE"
  exit 1
fi

PORT_SCAN=$(grep -c "CST109 PORT SCAN SYN" "$ALERT_FILE" || true)
ICMP_FLOOD=$(grep -c "CST109 ICMP FLOOD" "$ALERT_FILE" || true)
SSH_BRUTE=$(grep -c "CST109 SSH BRUTE FORCE" "$ALERT_FILE" || true)

{
  echo "PORT_SCAN=$PORT_SCAN"
  echo "ICMP_FLOOD=$ICMP_FLOOD"
  echo "SSH_BRUTE_FORCE=$SSH_BRUTE"
  echo "LATEST_ALERTS"
  cat "$ALERT_FILE"
} > "$OUT_FILE"

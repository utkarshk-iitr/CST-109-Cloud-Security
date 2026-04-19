#!/usr/bin/env bash
set -e

ALERT_FILE=${ALERT_FILE:-/var/log/snort/snort.alert.fast}
OUT_FILE=${OUT_FILE:-../../logs/ids.txt}

PORT_SCAN=$(grep -c "CST109 PORT SCAN SYN" "$ALERT_FILE" || true)
ICMP_FLOOD=$(grep -c "ICMP" "$ALERT_FILE" || true)
SSH_BRUTE=$(grep -c "TCP" "$ALERT_FILE" || true)

{
  echo "PORT_SCAN=$PORT_SCAN"
  echo "ICMP_FLOOD=$ICMP_FLOOD"
  echo "SSH_BRUTE_FORCE=$SSH_BRUTE"
  echo "LATEST_ALERTS"
  cat "$ALERT_FILE"
} > "$OUT_FILE"

#!/usr/bin/env bash
set -e

TARGET_IP=${TARGET_IP:-127.0.0.1}
SSH_USER=${SSH_USER:-invaliduser}

sudo nmap -sS -p 1-1024 "$TARGET_IP"
sudo hping3 --icmp -i u1000 -c 120 "$TARGET_IP"
for i in $(seq 1 12); do ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 "$SSH_USER@$TARGET_IP" "exit" || true; done

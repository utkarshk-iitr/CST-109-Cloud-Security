#!/usr/bin/env bash
set -e

TARGET_IP=10.81.12.36
SSH_USER=invaliduser

sudo nmap -sS -p 1-1024 "$TARGET_IP"
sudo nping --icmp --rate 1000 -c 120 "$TARGET_IP"
for i in $(seq 1 12); do ssh -p 22 -o StrictHostKeyChecking=no -o ConnectTimeout=2 "$SSH_USER@$TARGET_IP" "exit" || true; done

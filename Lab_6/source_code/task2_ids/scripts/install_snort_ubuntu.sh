#!/usr/bin/env bash
set -e

sudo apt update
sudo apt install -y snort nmap hping3 hydra
sudo cp ../snort/local.rules /etc/snort/rules/local.rules
sudo grep -q "include \$RULE_PATH/local.rules" /etc/snort/snort.conf || echo "include \$RULE_PATH/local.rules" | sudo tee -a /etc/snort/snort.conf > /dev/null

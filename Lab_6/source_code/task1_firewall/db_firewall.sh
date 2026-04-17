#!/usr/bin/env bash
set -e

WEB_IP=${WEB_IP:-10.0.0.20}
ADMIN_IP=${ADMIN_IP:-10.0.0.10}
DB_PORT=${DB_PORT:-3306}

iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp -s "$WEB_IP" --dport "$DB_PORT" -j ACCEPT
iptables -A INPUT -p tcp -s "$ADMIN_IP" --dport 22 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT

iptables-save

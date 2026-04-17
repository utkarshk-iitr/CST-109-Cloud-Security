#!/usr/bin/env bash
set -e

CLIENT_NET=${CLIENT_NET:-10.0.0.0/24}
ADMIN_IP=${ADMIN_IP:-10.0.0.10}
DB_IP=${DB_IP:-10.0.0.30}
WEB_HTTP_PORT=${WEB_HTTP_PORT:-80}
WEB_HTTPS_PORT=${WEB_HTTPS_PORT:-443}
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

iptables -A INPUT -p tcp -s "$CLIENT_NET" --dport "$WEB_HTTP_PORT" -j ACCEPT
iptables -A INPUT -p tcp -s "$CLIENT_NET" --dport "$WEB_HTTPS_PORT" -j ACCEPT
iptables -A INPUT -p tcp -s "$ADMIN_IP" --dport 22 -j ACCEPT

iptables -A OUTPUT -p tcp -d "$DB_IP" --dport "$DB_PORT" -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

iptables-save

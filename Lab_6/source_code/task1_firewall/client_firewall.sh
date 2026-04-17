#!/usr/bin/env bash
set -e

WEB_IP=${WEB_IP:-10.0.0.20}
WEB_HTTP_PORT=${WEB_HTTP_PORT:-80}
WEB_HTTPS_PORT=${WEB_HTTPS_PORT:-443}

iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A OUTPUT -p tcp -d "$WEB_IP" --dport "$WEB_HTTP_PORT" -j ACCEPT
iptables -A OUTPUT -p tcp -d "$WEB_IP" --dport "$WEB_HTTPS_PORT" -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

iptables -A INPUT -p icmp -j ACCEPT

iptables-save

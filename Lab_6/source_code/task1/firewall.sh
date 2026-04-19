#!/usr/bin/env bash
set -e

iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp -s 10.81.35.164 --dport 8080 -j ACCEPT
iptables -A OUTPUT -p tcp -d 10.81.12.36 --dport 3306 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j DROP
iptables -A INPUT -p tcp --dport 22 -j DROP
iptables -A OUTPUT -p tcp --dport 21 -j DROP
iptables -A OUTPUT -p tcp --dport 25 -j DROP
iptables -A INPUT -p icmp -j ACCEPT
iptables -A OUTPUT -p icmp -j ACCEPT

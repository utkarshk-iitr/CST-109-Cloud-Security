#!/usr/bin/env bash
set -e

iptables -F
iptables -X
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP


iptables -A INPUT -p tcp -s 127.0.0.1/32 --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

iptables -A OUTPUT -p tcp --sport 8080 -d 127.0.0.1 --dport 3306 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 21 -j DROP
iptables -A OUTPUT -p tcp --dport 25 -j DROP
iptables -A OUTPUT -p icmp -j ACCEPT


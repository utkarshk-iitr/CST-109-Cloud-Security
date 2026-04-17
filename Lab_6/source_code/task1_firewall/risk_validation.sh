#!/usr/bin/env bash
set -e

WEB_IP=${WEB_IP:-10.0.0.20}
DB_IP=${DB_IP:-10.0.0.30}
DB_PORT=${DB_PORT:-3306}

printf "WEB HTTP check\n"
nc -vz "$WEB_IP" 80 || true
printf "WEB HTTPS check\n"
nc -vz "$WEB_IP" 443 || true
printf "DIRECT DB check\n"
nc -vz "$DB_IP" "$DB_PORT" || true

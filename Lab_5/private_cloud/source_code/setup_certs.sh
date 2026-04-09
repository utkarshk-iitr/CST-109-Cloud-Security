#!/bin/bash
cd /home/utk/Desktop/UtkKumar/CST-109-Cloud-Security/Lab_5/private_cloud/source_code
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"

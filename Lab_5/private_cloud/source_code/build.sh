#!/bin/bash
set -e

cd /home/utk/Desktop/UtkKumar/CST-109-Cloud-Security/Lab_5/private_cloud/source_code

echo "Installing required Python package..."
python3 -m pip install --user cryptography

if [[ ! -f certs/server.crt || ! -f certs/server.key ]]; then
	echo "TLS certs not found. Generating self-signed certificate..."
	bash setup_certs.sh
fi

echo "Build/setup completed."
echo "Start services in separate terminals:"
echo "1) python3 iam_server/iam_server.py"
echo "2) python3 backend_servers/backend_server.py 1 7001"
echo "3) python3 backend_servers/backend_server.py 2 7002"
echo "4) python3 api_gateway/api_gateway.py"
echo "5) python3 client/client.py"

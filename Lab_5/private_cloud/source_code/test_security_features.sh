#!/bin/bash
set -e

cd /home/utk/Desktop/UtkKumar/CST-109-Cloud-Security/Lab_5/private_cloud/source_code

echo "Checking Python security dependency..."
python3 -c "from cryptography.fernet import Fernet; print('cryptography available')"

echo "Checking TLS certificate files..."
if [[ -f certs/server.crt && -f certs/server.key ]]; then
	echo "TLS cert files are present."
else
	echo "TLS cert files missing. Run: bash setup_certs.sh"
	exit 1
fi

echo "Please start the following in separate terminals:"
echo "1. python3 iam_server/iam_server.py"
echo "2. python3 backend_servers/backend_server.py 1 7001"
echo "3. python3 backend_servers/backend_server.py 2 7002"
echo "4. python3 api_gateway/api_gateway.py"
echo "5. python3 client/client.py"

echo "Validation checklist:"
echo "- Run LOGIN and verify token + refresh_token are returned."
echo "- Trigger invalid token attempts and verify blocking/alerts in logs."
echo "- Use SHOW_ENCRYPTED_RECORDS as admin and confirm ciphertext in storage file."
echo "- Wait for key rotation interval and verify keyring update in security/keyring.json."


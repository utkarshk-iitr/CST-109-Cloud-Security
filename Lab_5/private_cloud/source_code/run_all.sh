#!/bin/bash

WORK_DIR="/home/utk/Desktop/UtkKumar/CST-109-Cloud-Security/Lab_5/private_cloud/source_code"
cd "$WORK_DIR"
echo "Making certificates"
bash certs/make_certs.sh
sleep 2

run_in_terminal() {
    local cmd="$1"
    local label="$2"
    gnome-terminal --title="$label" -- bash -c "cd '$WORK_DIR' && $cmd; exec bash" &
}

echo "Starting applications"
run_in_terminal "python3 iam_server.py" "IAM Server"
sleep 1
run_in_terminal "python3 backend_server.py 1 7001" "Backend Server 1"
sleep 1
run_in_terminal "python3 backend_server.py 2 7002" "Backend Server 2"
sleep 1
run_in_terminal "python3 api_gateway.py" "API Gateway"
sleep 2
run_in_terminal "python3 client.py" "Client"

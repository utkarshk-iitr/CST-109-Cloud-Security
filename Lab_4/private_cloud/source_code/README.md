# Lab 4: Distributed IAM

This implementation extends the Lab 3 style architecture into an IAM-focused distributed system:

- API Gateway
- IAM Server (register/login, JWT generation)
- Multiple backend resource servers
- Client for normal flows and attack simulations
- Centralized security logs

## Architecture

Client -> API Gateway -> IAM Server (REGISTER, LOGIN)
Client -> API Gateway -> Backend Server 1/2 (protected APIs with JWT + RBAC)

## Default Users

- admin / admin123 (role: admin)
- user1 / user123 (role: user)

## Run Instructions

Open 5 terminals from source_code and run:

1) IAM server
python3 iam_server/iam_server.py

2) Backend server 1
python3 backend_servers/backend_server.py 1 7001

3) Backend server 2
python3 backend_servers/backend_server.py 2 7002

4) API gateway
python3 api_gateway/api_gateway.py

5) Client
python3 client/client.py

## Authors -

Utkarsh Kumar
Adesh Palkar
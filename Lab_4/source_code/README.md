# Lab 4: Distributed IAM with API Gateway, JWT, RBAC, and Attack Mitigation

This implementation extends the Lab 3 style architecture into an IAM-focused distributed system:

- API Gateway
- IAM Server (register/login, JWT generation)
- Multiple backend resource servers
- Client for normal flows and attack simulations
- Centralized security logs

## Architecture

Client -> API Gateway -> IAM Server (REGISTER, LOGIN)
Client -> API Gateway -> Backend Server 1/2 (protected APIs with JWT + RBAC)

## Features Mapped to Assignment

1. Basic Authentication + JWT
- Register and login using username/password
- JWT generated after successful login
- Protected routes require token
- Successful and failed login attempts logged

2. Role-Based Access Control (RBAC)
- Roles: admin, user
- Role included in JWT
- Admin-only endpoint: GET_ADMIN_REPORT
- Authorized and unauthorized access attempts logged

3. Attack Simulations
- Brute-force login simulation in client
- Invalid/tampered token simulation in client
- Failed logins and unauthorized access recorded in logs

4. Automated Security Mechanisms
- Token expiration (`exp` claim in JWT)
- Block repeated invalid-token requests per IP
- Account lockout after repeated failed logins
- Mitigation actions auto-triggered and logged

## Folder Structure

source_code/
- api_gateway/api_gateway.py
- iam_server/iam_server.py
- backend_servers/backend_server.py
- client/client.py
- common/config.py
- common/jwt_utils.py
- common/logger_utils.py
- common/socket_utils.py

Logs are stored in:
- ../logs/auth.log
- ../logs/access.log
- ../logs/threats.log
- ../logs/mitigation.log
- ../logs/gateway.log
- ../logs/iam_server.log
- ../logs/backend_1.log
- ../logs/backend_2.log

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

## Suggested Demo Flow

1. Register a new user
2. Login and call GET_PROFILE (allowed)
3. As user role, call GET_ADMIN_REPORT (should be denied)
4. Run brute-force simulation (option 5) to trigger lockout
5. Run invalid token simulation (option 6) to trigger token mitigation/block
6. Wait for token expiry and call GET_PROFILE again

## Notes

- This project uses a built-in HS256 JWT implementation in `common/jwt_utils.py` (no third-party dependency).
- For production systems, use a proven JWT library, HTTPS/TLS, secure secret management, persistent storage, and stronger password policies.

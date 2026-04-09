# Lab 5: Private Distributed Cloud Security

This Lab 5 implementation extends the Lab 4 distributed architecture with data protection controls, automated mitigations, and periodic key/token lifecycle mechanisms.

## Implemented Security Features

### 1) Data Protection

- Encryption at rest across distributed storage nodes:
	- Each backend node stores encrypted JSON records in `storage_nodes/backend_*/encrypted_records.json`.
	- Plain data is encrypted with Fernet before being written to disk.
- Encryption in transit:
	- TLS is enabled for all socket links:
		- Client -> API Gateway
		- API Gateway -> IAM Server
		- API Gateway -> Backend nodes
- Key management:
	- Central key ring file: `security/keyring.json`
	- Active key + historical keys retained for seamless decrypt after rotation.
	- Periodic key rotation thread runs in the API Gateway.

### 2) Automated Security Measures

- IP blocking after repeated invalid token attempts.
- Temporary user blocking after repeated unauthorized access attempts.
- Temporary node access restriction for suspicious users.
- Alert logs for abnormal access behavior:
	- frequent access bursts
	- repeated invalid tokens
	- unauthorized role access
	- unknown backend identity behavior

### 3) Periodic Rotation & Token Renewal

- Key rotation:
	- Runs periodically and updates shared key ring.
	- Existing data remains decryptable using retained historical keys.
- Token renewal:
	- IAM issues both access token and refresh token at login.
	- Client performs periodic refresh-token based renewal.

## Architecture

Client -> API Gateway -> IAM Server (REGISTER, LOGIN, RENEW_TOKEN)
Client -> API Gateway -> Backend Server 1/2 (JWT + RBAC + encrypted-at-rest records)

## Default Users

- admin / admin123 (role: admin)
- user1 / user123 (role: user)

## Setup

1. Install dependencies:
	 - `pip install cryptography`
2. Generate TLS certificate and key (if not already present):
	 - `bash setup_certs.sh`

## Run

Open 5 terminals from `Lab_5/private_cloud/source_code`:

1. `python3 iam_server.py`
2. `python3 backend_server.py 1 7001`
3. `python3 backend_server.py 2 7002`
4. `python3 api_gateway.py`
5. `python3 client.py`

## Suggested Screenshots for Report

1. TLS enabled logs from gateway/backend/IAM startup.
2. Encrypted storage file content from `storage_nodes/backend_1/encrypted_records.json`.
3. Client output for token renewal and protected route access.
4. Alert/mitigation logs from:
	 - `logs/threats.log`
	 - `logs/mitigation.log`
	 - `logs/auth.log`

## Authors

Utkarsh Kumar
Adesh Palkar
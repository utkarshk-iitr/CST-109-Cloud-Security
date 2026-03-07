# Assignment 3: Secure Cloud Application Architecture

## Architecture Overview

```
Client  --->  API Gateway (8080)  --->  Application Server (5000)  --->  Storage Servers (6001-6004)
                  |                            |                              |
          Rate Limiting               Auth + RBAC                    Integrity Checks
          IP Blocking                 Token Management               Chunk Storage
          Threat Detection            File Operations                Audit Logging
                  |                            |                              |
                  +------- All logs go to logs/ directory --------+
```

### Trust Boundaries
- **B1**: Client <-> API Gateway (untrusted -> boundary)
- **B2**: API Gateway <-> Application Server (boundary -> trusted)
- **B3**: Client <-> Storage Servers (untrusted -> trusted)

## Components

| Component | Location | Port | Description |
|-----------|----------|------|-------------|
| Client | `client/client.py` | - | CLI client + attack simulator |
| API Gateway | `api_gateway/api_gateway.py` | 8080 | Reverse proxy with security |
| App Server | `application_server/application_server.py` | 5000 | Auth, RBAC, file management |
| Storage Servers | `storage_servers/storage_server.py` | 6001-6004 | File chunk storage |
| Threat Modeler | `security_modules/threat_modeler.py` | - | STRIDE threat analysis |
| Mitigation Engine | `security_modules/mitigation_engine.py` | - | Mitigation rules |
| Monitor | `monitoring/monitor.py` | - | Log monitoring & reports |

## How to Run

All components use `127.0.0.1` (localhost) by default.

### Step 1: Start Storage Servers (open 4 separate terminals)
```bash
cd source_code/storage_servers
python3 storage_server.py 1
python3 storage_server.py 2
python3 storage_server.py 3
python3 storage_server.py 4
```

### Step 2: Start Application Server (new terminal)
```bash
cd source_code/application_server
python3 application_server.py
```

### Step 3: Start API Gateway (new terminal)
```bash
cd source_code/api_gateway
python3 api_gateway.py
```

### Step 4: Run Client (new terminal)
```bash
cd source_code/client
python3 client.py
```

## Default Users

| Username | Password | Role | Permissions |
|----------|----------|------|-------------|
| admin | admin123 | Admin | Upload, Download, List, Delete |
| user1 | user123 | User | Upload, Download, List |
| readonly | read123 | Read-only | Download, List |

## Security Features

### Task 2: Authentication & Authorization
- Token-based auth (secure random tokens, 24h expiry, IP-bound)
- Role-based access control (admin/user/readonly)
- All auth events logged to `auth.log`

### Task 3: Automated Threat Modeling (STRIDE)
```bash
cd source_code/security_modules
python3 threat_modeler.py
```
Identifies 10 threats across all STRIDE categories with risk scores.

### Task 4: Automated Risk Mitigation
- **Rate Limiting**: 30 requests/min per IP at gateway
- **Account Lockout**: 5 failed logins -> 5 min lockout
- **IP Blocking**: 100 req/min -> auto-block for 10 min
- All mitigations trigger automatically, logged to `mitigation.log`

```bash
cd source_code/security_modules
python3 mitigation_engine.py
```

### Task 5: Resilience Testing (Attack Simulations)
Use client menu options 6 and 7:
- **Option 6**: Brute-force attack simulation
- **Option 7**: Denial-of-Service attack simulation

Both report detection time, mitigation time, and system availability.

## Monitoring

### Generate Security Report
```bash
cd source_code/monitoring
python3 monitor.py
```

### Live Monitoring (real-time log watching)
```bash
cd source_code/monitoring
python3 monitor.py --live
```

## Log Files

| File | Contents |
|------|----------|
| `logs/auth.log` | Login successes and failures |
| `logs/threats.log` | Detected threats (brute-force, DoS, etc.) |
| `logs/mitigation.log` | Automated mitigation actions |
| `logs/gateway.log` | API Gateway request log |
| `logs/application_server.log` | App server operations |
| `logs/storage_*.log` | Storage server operations |

## Directory Structure

```
Assign3_Week2/
├── source_code/
│   ├── client/client.py
│   ├── api_gateway/api_gateway.py
│   ├── application_server/application_server.py
│   ├── storage_servers/storage_server.py
│   ├── security_modules/
│   │   ├── threat_modeler.py
│   │   └── mitigation_engine.py
│   ├── monitoring/monitor.py
│   └── README.md
├── logs/
│   ├── auth.log
│   ├── threats.log
│   └── mitigation.log
├── storage_1/ through storage_4/
├── diagrams/
├── screenshots/
└── report/
```

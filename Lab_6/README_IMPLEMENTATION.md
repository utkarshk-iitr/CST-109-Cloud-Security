CST-109 Assignment 6 Implementation

Directory Map
- source_code/task1_three_tier: 3-tier web and database access code
- source_code/task1_firewall: iptables least-privilege rules
- source_code/task2_ids: Snort custom rules and attack scripts
- source_code/task3_siem: ELK ingestion pipeline and analysis utilities
- source_code/task4_traffic: capture and analysis script for Wireshark/tshark task
- logs: place collected logs here for submission
- screenshots: place evidence screenshots here for submission

Task 1: Network Access Control and Least Privilege

Localhost Port Map
- Client CLI: local process (no listening port)
- Web API: 127.0.0.1:8080
- Database: 127.0.0.1:3306

Step 1: Database Setup on Localhost
1. sudo apt update
2. sudo apt install -y mysql-server
3. sudo systemctl enable --now mysql
4. sudo mysql -e "CREATE DATABASE IF NOT EXISTS cloud_security;"
5. sudo mysql -e "CREATE USER IF NOT EXISTS 'cloud_user'@'127.0.0.1' IDENTIFIED BY 'cloud_pass_123';"
6. sudo mysql -e "GRANT ALL PRIVILEGES ON cloud_security.* TO 'cloud_user'@'127.0.0.1'; FLUSH PRIVILEGES;"

Step 2: Web and DB Init on Localhost
1. cd Lab_6/source_code/task1_three_tier
2. python3 -m venv .venv
3. source .venv/bin/activate
4. pip install -r requirements.txt
5. If your venv was created before this update, run: pip install cryptography
6. export WEB_HOST=127.0.0.1
7. export WEB_PORT=8080
8. export DB_HOST=127.0.0.1
9. export DB_PORT=3306
10. export DB_USER=cloud_user
11. export DB_PASSWORD=cloud_pass_123
12. export DB_NAME=cloud_security
13. python3 db_init.py
14. python3 web_server.py

Step 3: Validate Localhost 3-Tier Access
1. Open another terminal
2. cd Lab_6/source_code/task1_three_tier
3. source .venv/bin/activate
4. python3 client.py --base-url http://127.0.0.1:8080 --mode web-list
5. python3 client.py --base-url http://127.0.0.1:8080 --mode web-add --name test1 --email test1@example.com
6. python3 client.py --base-url http://127.0.0.1:8080 --mode direct-db-test --db-host 127.0.0.1 --db-port 3306

Step 4: Optional Local Firewall Script Run
1. cd Lab_6/source_code/task1_firewall
2. sudo WEB_IP=127.0.0.1 ./client_firewall.sh
3. sudo CLIENT_NET=127.0.0.1/32 ADMIN_IP=127.0.0.1 DB_IP=127.0.0.1 WEB_HTTP_PORT=8080 WEB_HTTPS_PORT=8443 DB_PORT=3306 ./web_firewall.sh
4. sudo WEB_IP=127.0.0.1 ADMIN_IP=127.0.0.1 DB_PORT=3306 ./db_firewall.sh
5. DB_IP=127.0.0.1 WEB_IP=127.0.0.1 DB_PORT=3306 ./risk_validation.sh

Note for Localhost Mode
- With all components on one host, strict identity-based separation between client process and web process using only IP source is limited.
- For strict network-policy proof, run separate containers or namespaces and reuse the same scripts with container IPs.

Expected Result
- Web API access works on 127.0.0.1:8080
- Client can access DB through the web API flow
- Direct client to DB connectivity test is available from client.py

Task 2: IDS with Snort

Step 1: Install and Configure Snort on Localhost
1. cd Lab_6/source_code/task2_ids/scripts
2. ./install_snort_ubuntu.sh
3. sudo cp ../snort/local.rules /etc/snort/rules/local.rules
4. sudo grep -q "include \$RULE_PATH/local.rules" /etc/snort/snort.conf || echo "include \$RULE_PATH/local.rules" | sudo tee -a /etc/snort/snort.conf > /dev/null

Step 2: Start Snort in NIDS Mode
1. sudo snort -i lo -A fast -q -c /etc/snort/snort.conf -l /var/log/snort

Step 3: Trigger Controlled Attacks on Localhost
1. cd Lab_6/source_code/task2_ids/scripts
2. TARGET_IP=127.0.0.1 ./trigger_attacks.sh

Step 4: Build Alert Summary
1. cd Lab_6/source_code/task2_ids/scripts
2. ALERT_FILE=/var/log/snort/alert OUT_FILE=../../../logs/ids_alert_summary.txt ./snort_alert_report.sh

Expected Result
- Alerts for port scan, ICMP flood, and unauthorized SSH attempts in /var/log/snort/alert

Task 3: SIEM Integration with ELK

Step 1: Install ELK Components on Localhost
1. Install Elasticsearch, Logstash, and Filebeat
2. Ensure Elasticsearch is reachable at http://127.0.0.1:9200

Step 2: Configure Logstash Pipeline
1. sudo cp Lab_6/source_code/task3_siem/logstash/snort_pipeline.conf /etc/logstash/conf.d/snort_pipeline.conf
2. sudo systemctl restart logstash

Step 3: Configure Filebeat Shipping
1. sudo cp Lab_6/source_code/task3_siem/filebeat/filebeat_snort.yml /etc/filebeat/filebeat.yml
2. sudo systemctl restart filebeat

Step 4: Validate Index Ingestion
1. cd Lab_6/source_code/task3_siem/scripts
2. ./elastic_index_check.sh

Step 5: Produce Local Threat Analytics
1. python3 alert_analytics.py --alert-file /var/log/snort/alert > ../../../logs/siem_local_analytics.json

Expected Result
- ids-snort-* index populated
- Threat frequency, source IP distribution, and protocol distribution available

Task 4: Network Traffic Analysis

Step 1: Capture Traffic for Less Than 5 Minutes
1. cd Lab_6/source_code/task4_traffic
2. IFACE=lo DURATION=180 OUT_DIR=./output ./capture_and_analyze.sh

Step 2: Fill Report Template
1. Open report_outline.md
2. Use output/sessions.txt for session details
3. Use output/tcp_handshake.txt for SYN, SYN-ACK, ACK sequence
4. Use output/dns_queries.txt for three domain queries and responses
5. Use output/plaintext_vs_tls.txt for HTTP vs TLS analysis

Submission Evidence Checklist
- Task 1 firewall rule output from all three nodes
- Task 1 success and blocked access test outputs
- Snort custom rule file and attack alerts
- SIEM index checks and at least one dashboard screenshot
- Packet capture outputs and completed Task 4 report
- Place logs in Lab_6/logs and screenshots in Lab_6/screenshots

Reset Commands
- To clear firewall policy on a node: sudo Lab_6/source_code/task1_firewall/reset_firewall.sh

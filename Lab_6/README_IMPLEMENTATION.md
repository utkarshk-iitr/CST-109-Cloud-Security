CST-109 Assignment 6 Implementation

Directory Map
- source_code/task1: 3-tier app and firewall scripts
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
5. sudo mysql -e "CREATE USER IF NOT EXISTS 'cst_user'@'127.0.0.1' IDENTIFIED BY 'cst_109';"
6. sudo mysql -e "GRANT ALL PRIVILEGES ON cloud_security.* TO 'cst_user'@'127.0.0.1'; FLUSH PRIVILEGES;"

Step 2: Web and DB Init on Localhost
1. cd Lab_6/source_code/task1
13. python3 db_init.py
14. python3 web_server.py

Step 3: Validate Localhost 3-Tier Access
1. Open another terminal
2. cd Lab_6/source_code/task1
4. python3 client.py --mode web-list
5. python3 client.py --mode web-add
6. python3 client.py --mode direct-db-test

Step 4: Optional Local Firewall Script Run
1. cd Lab_6/source_code/task1
2. sudo WEB_IP=127.0.0.1 ./client_firewall.sh
3. sudo CLIENT_NET=127.0.0.1/32 ADMIN_IP=127.0.0.1 DB_IP=127.0.0.1 WEB_HTTP_PORT=8080 WEB_HTTPS_PORT=8443 DB_PORT=3306 ./web_firewall.sh
4. sudo WEB_IP=127.0.0.1 ADMIN_IP=127.0.0.1 DB_PORT=3306 ./db_firewall.sh
5. DB_IP=127.0.0.1 WEB_IP=127.0.0.1 WEB_HTTP_PORT=8080 WEB_HTTPS_PORT=8443 DB_PORT=3306 ./risk_validation.sh

Note for Localhost Mode
- With all components on one host, strict identity-based separation between client process and web process using only IP source is limited.
- For strict network-policy proof, run separate containers or namespaces and reuse the same scripts with container IPs.

Expected Result
- Web API access works on 127.0.0.1:8080
- Client can access DB through the web API flow
- Direct client to DB on localhost may still succeed because all processes share one host network

Task 2: IDS with Snort

Step 1: Install and Configure Snort on Server (10.81.12.36)
1. cd Lab_6/source_code/task2_ids/scripts
2. ./install_snort_ubuntu.sh
3. sudo cp ../snort/local.rules /etc/snort/rules/local.rules
4. sudo cp ../snort/snort_local_include.conf /etc/snort/snort_local_include.conf
5. sudo grep -q "include /etc/snort/snort_local_include.conf" /etc/snort/snort.conf || echo "include /etc/snort/snort_local_include.conf" | sudo tee -a /etc/snort/snort.conf > /dev/null
6. sudo sed -i 's/^include \$RULE_PATH\/local.rules/# include \$RULE_PATH\/local.rules/' /etc/snort/snort.conf

Step 2: Start Snort in NIDS Mode
1. sudo snort -i eth0 -A fast -q -c /etc/snort/snort.conf -l /var/log/snort

Step 3: Trigger Controlled Attacks from Client (10.81.35.164)
1. cd Lab_6/source_code/task2_ids/scripts
2. TARGET_IP=10.81.12.36 SSH_PORT=22 ./trigger_attacks.sh

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
- To clear firewall policy on a node: sudo Lab_6/source_code/task1/reset_firewall.sh

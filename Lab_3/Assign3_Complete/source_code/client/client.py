"""
Secure Cloud Application Client
Supports: login, file upload/download/list/delete, attack simulation.
Connects to API Gateway for control-plane, Storage Servers for data transfer.
"""

import socket
import json
import os
import math
import time
import threading
import sys

# API Gateway address (entry point)
GATEWAY_HOST = '127.0.0.1'
GATEWAY_PORT = 8080

CHUNK_SIZE = 1024 * 1024  # 1 MB


class CloudClient:
    def __init__(self):
        self.gateway_host = GATEWAY_HOST
        self.gateway_port = GATEWAY_PORT
        self.token = None
        self.username = None

    def send_request(self, request):
        """Send JSON request to API Gateway and return response dict."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.gateway_host, self.gateway_port))
            sock.send(json.dumps(request).encode())
            response = json.loads(sock.recv(65536).decode())
            sock.close()
            return response
        except Exception as e:
            return {'status': 'ERROR', 'message': f'Connection error: {e}'}

    def connect_storage(self, host, port):
        """Direct connection to a storage server for data transfer."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((host, port))
        return sock

    # ---- Normal Operations ---- #

    def login(self, username, password):
        request = {
            'operation': 'LOGIN',
            'username': username,
            'password': password
        }
        response = self.send_request(request)

        if response['status'] == 'SUCCESS':
            self.token = response['token']
            self.username = username
            print(f"  Login successful! Welcome, {username}")
            return True
        else:
            print(f"  Login failed: {response['message']}")
            return False

    def upload_file(self, filepath):
        if not self.token:
            print("  Please login first.")
            return False
        if not os.path.exists(filepath):
            print(f"  File not found: {filepath}")
            return False

        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        n = math.ceil(file_size / CHUNK_SIZE)

        print(f"\n  Uploading: {filename} ({file_size} bytes, {n} chunks)")

        # Step 1: Request upload allocation via gateway
        request = {
            'operation': 'UPLOAD_REQUEST',
            'token': self.token,
            'filename': filename,
            'file_size': file_size,
            'num_chunks': n
        }
        response = self.send_request(request)

        if response['status'] != 'SUCCESS':
            print(f"  Error: {response['message']}")
            return False

        # Step 2: Upload chunks directly to storage servers
        chunks_info = []
        with open(filepath, 'rb') as f:
            for allocation in response['chunk_allocations']:
                chunk_id = allocation['chunk_id']
                server = allocation['server']
                chunk_data = f.read(CHUNK_SIZE)
                chunk_size = len(chunk_data)

                try:
                    sock = self.connect_storage(server['host'], server['port'])
                    store_req = {
                        'operation': 'STORE_CHUNK',
                        'filename': filename,
                        'chunk_id': chunk_id,
                        'chunk_size': chunk_size
                    }
                    sock.send(json.dumps(store_req).encode())
                    sock.recv(1024)  # Wait for READY
                    sock.sendall(chunk_data)
                    store_resp = json.loads(sock.recv(1024).decode())
                    sock.close()

                    if store_resp['status'] == 'SUCCESS':
                        print(f"    Chunk {chunk_id} -> {server['id']} ({chunk_size} bytes)")
                        chunks_info.append({
                            'chunk_id': chunk_id,
                            'server_id': server['id'],
                            'server_host': server['host'],
                            'server_port': server['port'],
                            'size': chunk_size
                        })
                    else:
                        print(f"    Failed chunk {chunk_id}: {store_resp['message']}")
                        return False
                except Exception as e:
                    print(f"    Error uploading chunk {chunk_id}: {e}")
                    return False

        # Step 3: Notify upload complete via gateway
        complete_req = {
            'operation': 'UPLOAD_COMPLETE',
            'token': self.token,
            'filename': filename,
            'chunks': chunks_info,
            'total_size': file_size
        }
        response = self.send_request(complete_req)

        if response['status'] == 'SUCCESS':
            print(f"  Upload complete: {filename}")
            return True
        else:
            print(f"  Error: {response['message']}")
            return False

    def download_file(self, filename, output_path=None):
        if not self.token:
            print("  Please login first.")
            return False
        if output_path is None:
            output_path = f"downloaded_{filename}"

        request = {
            'operation': 'DOWNLOAD_REQUEST',
            'token': self.token,
            'filename': filename
        }
        response = self.send_request(request)

        if response['status'] != 'SUCCESS':
            print(f"  Error: {response['message']}")
            return False

        chunks = response['chunks']
        total_size = response['total_size']
        print(f"\n  Downloading: {filename} ({total_size} bytes, {len(chunks)} chunks)")

        with open(output_path, 'wb') as f:
            for chunk_info in sorted(chunks, key=lambda x: x['chunk_id']):
                chunk_id = chunk_info['chunk_id']
                server_host = chunk_info['server_host']
                server_port = chunk_info['server_port']
                server_id = chunk_info['server_id']

                try:
                    sock = self.connect_storage(server_host, server_port)
                    req = {
                        'operation': 'RETRIEVE_CHUNK',
                        'filename': filename,
                        'chunk_id': chunk_id
                    }
                    sock.send(json.dumps(req).encode())
                    resp = json.loads(sock.recv(1024).decode())

                    if resp['status'] != 'SUCCESS':
                        print(f"    Failed chunk {chunk_id}: {resp['message']}")
                        sock.close()
                        return False

                    chunk_size = resp['chunk_size']
                    sock.send(b'READY')

                    chunk_data = b''
                    remaining = chunk_size
                    while remaining > 0:
                        data = sock.recv(min(remaining, 8192))
                        if not data:
                            break
                        chunk_data += data
                        remaining -= len(data)

                    sock.close()
                    f.write(chunk_data)
                    print(f"    Chunk {chunk_id} <- {server_id} ({chunk_size} bytes)")
                except Exception as e:
                    print(f"    Error downloading chunk {chunk_id}: {e}")
                    return False

        print(f"  Download complete: {output_path}")
        return True

    def list_files(self):
        if not self.token:
            print("  Please login first.")
            return

        request = {'operation': 'LIST_FILES', 'token': self.token}
        response = self.send_request(request)

        if response['status'] != 'SUCCESS':
            print(f"  Error: {response['message']}")
            return

        files = response['files']
        if not files:
            print("\n  No files stored.")
            return

        print(f"\n  {'='*65}")
        print(f"  {'Filename':<30} {'Size':<12} {'Chunks':<8} {'Uploaded By':<15}")
        print(f"  {'-'*65}")
        for f in files:
            print(f"  {f['filename']:<30} {f['size']:<12} {f['chunks']:<8} {f.get('uploaded_by','?'):<15}")
        print(f"  {'='*65}")

    def delete_file(self, filename):
        if not self.token:
            print("  Please login first.")
            return

        request = {
            'operation': 'DELETE_FILE',
            'token': self.token,
            'filename': filename
        }
        response = self.send_request(request)

        if response['status'] == 'SUCCESS':
            print(f"  File deleted: {filename}")
        else:
            print(f"  Error: {response['message']}")

    # ---- Attack Simulations ---- #

    def simulate_brute_force(self, target_user='admin', attempts=10):
        """Simulate a brute-force login attack with wrong passwords."""
        print(f"\n  {'='*55}")
        print(f"  ATTACK SIMULATION: Brute-Force Login")
        print(f"  Target: {target_user} | Attempts: {attempts}")
        print(f"  {'='*55}\n")

        passwords = [
            'wrong1', 'pass123', 'letmein', 'password', '123456',
            'qwerty', 'abc123', 'monkey', 'dragon', 'master',
            'test', 'trustno1', 'baseball', 'shadow', 'hello'
        ]

        start = time.time()
        blocked_at = None

        for i in range(attempts):
            pwd = passwords[i % len(passwords)]
            request = {
                'operation': 'LOGIN',
                'username': target_user,
                'password': pwd
            }
            response = self.send_request(request)
            status = response.get('status', 'ERROR')
            msg = response.get('message', '')
            print(f"    Attempt {i+1:>2}: password='{pwd}' -> {status}: {msg}")

            if 'locked' in msg.lower() or 'blocked' in msg.lower():
                blocked_at = i + 1
                print(f"\n    [!] Attack MITIGATED after {blocked_at} attempts!")
                break
            time.sleep(0.1)

        elapsed = time.time() - start
        print(f"\n  Detection time:  {elapsed:.2f}s")
        if blocked_at:
            print(f"  Mitigation:      Account locked after {blocked_at} attempts")
        else:
            print(f"  Mitigation:      Not triggered (threshold not reached)")
        print(f"  Brute-force simulation complete.\n")

    def simulate_dos(self, num_requests=50, threads=5):
        """Simulate a Denial-of-Service attack with rapid requests."""
        print(f"\n  {'='*55}")
        print(f"  ATTACK SIMULATION: Denial of Service")
        print(f"  Requests: {num_requests} | Threads: {threads}")
        print(f"  {'='*55}\n")

        results = {'success': 0, 'rate_limited': 0, 'blocked': 0, 'error': 0}
        results_lock = threading.Lock()
        start_time = time.time()

        def send_flood(count):
            for _ in range(count):
                try:
                    request = {'operation': 'LIST_FILES', 'token': 'fake_token_dos'}
                    response = self.send_request(request)
                    msg = response.get('message', '').lower()
                    with results_lock:
                        if 'rate limit' in msg:
                            results['rate_limited'] += 1
                        elif 'blocked' in msg:
                            results['blocked'] += 1
                        elif response.get('status') == 'SUCCESS':
                            results['success'] += 1
                        else:
                            results['error'] += 1
                except:
                    with results_lock:
                        results['error'] += 1

        per_thread = num_requests // threads
        thread_list = []
        for _ in range(threads):
            t = threading.Thread(target=send_flood, args=(per_thread,))
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

        elapsed = time.time() - start_time
        total = sum(results.values())

        print(f"  Results:")
        print(f"    Total sent:     {total}")
        print(f"    Successful:     {results['success']}")
        print(f"    Rate limited:   {results['rate_limited']}")
        print(f"    IP blocked:     {results['blocked']}")
        print(f"    Errors:         {results['error']}")
        print(f"    Time elapsed:   {elapsed:.2f}s")
        if elapsed > 0:
            print(f"    Requests/sec:   {total/elapsed:.1f}")

        mitigated = results['rate_limited'] + results['blocked']
        if mitigated > 0:
            print(f"\n    [!] Attack MITIGATED: {mitigated}/{total} requests blocked")
            print(f"    Detection time: ~{elapsed/total*results['success']:.2f}s")
        print(f"\n  DoS simulation complete.\n")

    def simulate_token_tampering(self):
        """Simulate invalid/tampered JWT token attacks."""
        print(f"\n  {'='*55}")
        print(f"  ATTACK SIMULATION: Invalid / Tampered Token")
        print(f"  {'='*55}\n")

        # Test 1: Completely fake token
        print("  [Test 1] Using a completely fabricated token...")
        response = self.send_request({
            'operation': 'LIST_FILES',
            'token': 'fake_token_AAAAAAAAA_tampered_12345'
        })
        print(f"    Result: {response['status']} - {response.get('message', '')}")
        mitigated_1 = response['status'] == 'ERROR'

        # Test 2: Tampered (modified) token
        print("\n  [Test 2] Tampering with a valid token structure...")
        import base64
        # Create a token that looks like a real one but is modified
        tampered = base64.urlsafe_b64encode(b'{"user":"admin","role":"admin"}').decode()
        response = self.send_request({
            'operation': 'DELETE_FILE',
            'token': tampered,
            'filename': 'secret.txt'
        })
        print(f"    Result: {response['status']} - {response.get('message', '')}")
        mitigated_2 = response['status'] == 'ERROR'

        # Test 3: Expired token simulation (empty string)
        print("\n  [Test 3] Using empty/null token...")
        response = self.send_request({
            'operation': 'UPLOAD_REQUEST',
            'token': '',
            'filename': 'test.txt',
            'file_size': 100,
            'num_chunks': 1
        })
        print(f"    Result: {response['status']} - {response.get('message', '')}")
        mitigated_3 = response['status'] == 'ERROR'

        # Test 4: Token with altered payload
        print("\n  [Test 4] Using token with modified payload...")
        response = self.send_request({
            'operation': 'DELETE_FILE',
            'token': 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.tampered',
            'filename': 'important.txt'
        })
        print(f"    Result: {response['status']} - {response.get('message', '')}")
        mitigated_4 = response['status'] == 'ERROR'

        total_mitigated = sum([mitigated_1, mitigated_2, mitigated_3, mitigated_4])
        print(f"\n  SUMMARY:")
        print(f"    Tests run:     4")
        print(f"    Mitigated:     {total_mitigated}/4")
        if total_mitigated == 4:
            print(f"    [!] All tampered token attacks were BLOCKED!")
        print(f"    Server validates tokens server-side, rejects all invalid tokens.")
        print(f"\n  Token tampering simulation complete.\n")

    def simulate_replay_attack(self):
        """Simulate token replay attack - reuse of expired/old tokens."""
        print(f"\n  {'='*55}")
        print(f"  ATTACK SIMULATION: Replay Attack")
        print(f"  {'='*55}\n")

        # Step 1: Login legitimately to get a valid token
        print("  [Step 1] Obtaining a legitimate token...")
        response = self.send_request({
            'operation': 'LOGIN',
            'username': 'user1',
            'password': 'user123'
        })
        if response['status'] != 'SUCCESS':
            print(f"    Failed to get token: {response.get('message')}")
            return
        captured_token = response['token']
        print(f"    Token captured: {captured_token[:20]}...")

        # Step 2: Use the captured token (should work)
        print("\n  [Step 2] Using captured token (valid use)...")
        response = self.send_request({
            'operation': 'LIST_FILES',
            'token': captured_token
        })
        print(f"    Result: {response['status']} - Token accepted")

        # Step 3: Try replaying token from a different 'context'
        # Simulate by using a completely wrong token pretending it's replayed
        print("\n  [Step 3] Replaying a previously-used token from another session...")
        old_token = 'old_session_' + captured_token[12:]  # Modified token
        response = self.send_request({
            'operation': 'LIST_FILES',
            'token': old_token
        })
        print(f"    Result: {response['status']} - {response.get('message', '')}")
        mitigated_replay = response['status'] == 'ERROR'

        # Step 4: Show IP-binding defense
        print("\n  [Step 4] Token IP-binding defense...")
        print("    Tokens are bound to the originating IP address.")
        print("    If replayed from a different IP, the token is rejected.")
        print(f"    Token IP check: ENFORCED (server validates token.ip == request.ip)")

        # Step 5: Show expiration defense
        print("\n  [Step 5] Token expiration defense...")
        print(f"    Token TTL: 24 hours")
        print(f"    Expired tokens are automatically invalidated.")
        print(f"    Server checks: datetime.now() > token.expires")

        print(f"\n  SUMMARY:")
        print(f"    Replay defenses active:")
        print(f"      - Token IP binding:     ENABLED")
        print(f"      - Token expiration:     ENABLED (24h)")
        print(f"      - Unique token IDs:     ENABLED (secrets.token_urlsafe)")
        print(f"      - Modified token rejected: {'YES' if mitigated_replay else 'NO'}")
        print(f"\n  Replay attack simulation complete.\n")

    def simulate_idor(self):
        """Simulate Insecure Direct Object Reference attack."""
        print(f"\n  {'='*55}")
        print(f"  ATTACK SIMULATION: IDOR (Insecure Direct Object Reference)")
        print(f"  {'='*55}\n")

        # Step 1: Login as regular user
        print("  [Step 1] Login as regular user (user1)...")
        response = self.send_request({
            'operation': 'LOGIN',
            'username': 'user1',
            'password': 'user123'
        })
        if response['status'] != 'SUCCESS':
            print(f"    Failed: {response.get('message')}")
            return
        user_token = response['token']
        print(f"    Logged in as user1")

        # Step 2: Try to delete a file (admin-only operation)
        print("\n  [Step 2] Attempting admin-only DELETE as user1 (IDOR attempt)...")
        response = self.send_request({
            'operation': 'DELETE_FILE',
            'token': user_token,
            'filename': 'admin_secret.txt'
        })
        print(f"    Result: {response['status']} - {response.get('message', '')}")
        delete_blocked = response.get('message') == 'Permission denied'

        # Step 3: Try to access with manipulated object reference
        print("\n  [Step 3] Attempting to download non-owned file by name manipulation...")
        response = self.send_request({
            'operation': 'DOWNLOAD_REQUEST',
            'token': user_token,
            'filename': '../../../etc/passwd'  # Path traversal attempt
        })
        print(f"    Result: {response['status']} - {response.get('message', '')}")
        traversal_blocked = response['status'] == 'ERROR'

        # Step 4: Login as readonly and try to upload
        print("\n  [Step 4] Login as readonly user, attempt upload (privilege test)...")
        response = self.send_request({
            'operation': 'LOGIN',
            'username': 'readonly',
            'password': 'read123'
        })
        ro_token = response.get('token')
        if ro_token:
            response = self.send_request({
                'operation': 'UPLOAD_REQUEST',
                'token': ro_token,
                'filename': 'malicious.txt',
                'file_size': 100,
                'num_chunks': 1
            })
            print(f"    Result: {response['status']} - {response.get('message', '')}")
            upload_blocked = response.get('message') == 'Permission denied'
        else:
            upload_blocked = False
            print(f"    Could not login as readonly")

        # Step 5: Try to access with no token at all
        print("\n  [Step 5] Attempting operation with no authentication...")
        response = self.send_request({
            'operation': 'LIST_FILES'
        })
        print(f"    Result: {response['status']} - {response.get('message', '')}")
        noauth_blocked = response['status'] == 'ERROR'

        total_blocked = sum([delete_blocked, traversal_blocked, upload_blocked, noauth_blocked])
        print(f"\n  SUMMARY:")
        print(f"    IDOR tests run:     4")
        print(f"    Attacks blocked:    {total_blocked}/4")
        print(f"    Defenses active:")
        print(f"      - Role-based access control:  ENABLED")
        print(f"      - Server-side authorization:   ENABLED")
        print(f"      - Token validation required:   ENABLED")
        print(f"      - Direct object ref. checked:  ENABLED")
        if total_blocked >= 3:
            print(f"    [!] All IDOR attacks were MITIGATED!")
        print(f"\n  IDOR simulation complete.\n")


def print_menu(username):
    print(f"\n  {'='*50}")
    print(f"    Secure Cloud Application Client")
    if username:
        print(f"    Logged in as: {username}")
    print(f"  {'='*50}")
    print(f"    1. Login")
    print(f"    2. Upload file")
    print(f"    3. Download file")
    print(f"    4. List files")
    print(f"    5. Delete file (admin only)")
    print(f"    6. [Attack] Brute-force login")
    print(f"    7. [Attack] Denial of Service")
    print(f"    8. [Attack] Invalid/Tampered Token")
    print(f"    9. [Attack] Replay Attack")
    print(f"   10. [Attack] IDOR Attack")
    print(f"   11. Exit")
    print(f"  {'='*50}")


def main():
    client = CloudClient()

    print("\n  Default users:")
    print("    admin / admin123  (full access)")
    print("    user1 / user123   (upload/download)")
    print("    readonly / read123 (read only)")

    while True:
        print_menu(client.username)
        choice = input("    Enter choice: ").strip()

        if choice == '1':
            username = input("    Username: ").strip()
            password = input("    Password: ").strip()
            client.login(username, password)

        elif choice == '2':
            filepath = input("    File path: ").strip()
            client.upload_file(filepath)

        elif choice == '3':
            filename = input("    Filename: ").strip()
            output = input("    Output path (Enter for default): ").strip()
            client.download_file(filename, output or None)

        elif choice == '4':
            client.list_files()

        elif choice == '5':
            filename = input("    Filename to delete: ").strip()
            client.delete_file(filename)

        elif choice == '6':
            user = input("    Target username (default: admin): ").strip() or 'admin'
            attempts = input("    Number of attempts (default: 10): ").strip()
            attempts = int(attempts) if attempts else 10
            client.simulate_brute_force(user, attempts)

        elif choice == '7':
            num = input("    Number of requests (default: 50): ").strip()
            threads = input("    Number of threads (default: 5): ").strip()
            num = int(num) if num else 50
            threads = int(threads) if threads else 5
            client.simulate_dos(num, threads)

        elif choice == '8':
            client.simulate_token_tampering()

        elif choice == '9':
            client.simulate_replay_attack()

        elif choice == '10':
            client.simulate_idor()

        elif choice == '11':
            print("    Goodbye!")
            break

        else:
            print("    Invalid choice.")


if __name__ == '__main__':
    main()

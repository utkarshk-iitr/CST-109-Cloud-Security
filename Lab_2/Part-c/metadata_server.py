import socket
import json
import threading
import logging
import random
import time
from datetime import datetime

METADATA_SERVER_HOST = '10.81.1.104'
METADATA_SERVER_PORT = 5000
STORAGE_SERVERS = [
    {'host': '10.81.1.104', 'port': 6001, 'id': 'storage_1'},
    {'host': '10.81.1.104', 'port': 6002, 'id': 'storage_2'},
    {'host': '10.81.32.46', 'port': 6003, 'id': 'storage_3'},
    {'host': '10.81.32.46', 'port': 6004, 'id': 'storage_4'},
]
HEALTH_CHECK_INTERVAL = 10
HEALTH_CHECK_TIMEOUT = 2
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

logging.basicConfig(
    level=getattr(logging,"INFO"),
    format=LOG_FORMAT,
    handlers=[logging.FileHandler(f'metadata_server_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),logging.StreamHandler()]
)
logger = logging.getLogger('MetadataServer')

class MetadataServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.files = {}
        self.storage_servers = STORAGE_SERVERS.copy()
        self.server_health = {}
        for server in self.storage_servers:
            self.server_health[server['id']] = {'status': 'online','last_check': time.time(),'failed_checks': 0}
        self.lock = threading.Lock()
        self.health_check_thread = None
        self.running = True
        
    def get_online_servers(self):
        with self.lock:
            online = [s for s in self.storage_servers if self.server_health[s['id']]['status'] == 'online']
        return online
    
    def select_replica_servers(self, num_replicas):
        online_servers = self.get_online_servers()
        
        if len(online_servers) < num_replicas:
            logger.warning(f"Only {len(online_servers)} servers online, requested {num_replicas} replicas")
            num_replicas = len(online_servers)
        
        random.shuffle(online_servers)
        return online_servers[:num_replicas]
    
    def check_server_health(self, server):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(HEALTH_CHECK_TIMEOUT)
            sock.connect((server['host'], server['port']))
            request = {'operation': 'HEALTH_CHECK'}
            sock.send(json.dumps(request).encode())
            sock.recv(1024).decode()
            sock.close()
            
            return True
        except Exception as e:
            logger.debug(f"Health check failed for {server['id']}: {e}")
            return False
    
    def health_monitor(self):
        logger.info("Health monitor started")
        
        while self.running:
            time.sleep(HEALTH_CHECK_INTERVAL)
            
            for server in self.storage_servers:
                server_id = server['id']
                is_healthy = self.check_server_health(server)
                
                with self.lock:
                    current_status = self.server_health[server_id]['status']
                    
                    if is_healthy:
                        if current_status == 'offline':
                            logger.info(f"Server {server_id} is back ONLINE")
                        self.server_health[server_id]['status'] = 'online'
                        self.server_health[server_id]['failed_checks'] = 0
                    else:
                        self.server_health[server_id]['failed_checks'] += 1
                        
                        if self.server_health[server_id]['failed_checks'] >= 2:
                            if current_status == 'online':
                                logger.warning(f"Server {server_id} detected OFFLINE")
                            self.server_health[server_id]['status'] = 'offline'
                    
                    self.server_health[server_id]['last_check'] = time.time()
            
            with self.lock:
                online_count = sum(1 for s in self.server_health.values() if s['status'] == 'online')
                logger.info(f"Health check: {online_count}/{len(self.storage_servers)} servers online")
    
    def handle_client(self, client_socket, address):
        try:
            data = client_socket.recv(4096).decode()
            request = json.loads(data)
            
            op = request['operation']
            logger.info(f"Received request from {address}: {op}")
            
            
            if op == 'UPLOAD_REQUEST':
                response = self.handle_upload(request)
            elif op == 'DOWNLOAD_REQUEST':
                response = self.handle_download(request)
            elif op == 'LIST_FILES':
                response = self.list_files()
            elif op == 'UPLOAD_COMPLETE':
                response = self.handle_complete(request)
            elif op == 'SERVER_STATUS':
                response = self.server_status()
            else:
                response = {'status': 'ERROR', 'message': 'Unknown operation'}
            
            client_socket.send(json.dumps(response).encode())
            
        except Exception as e:
            logger.error(f"Error handling client {address}: {e}")
            error_response = {'status': 'ERROR', 'message': str(e)}
            client_socket.send(json.dumps(error_response).encode())
        finally:
            client_socket.close()
    
    def handle_upload(self, request):
        filename = request['filename']
        file_size = request['file_size']
        n = request['num_chunks']        
        online_servers = self.get_online_servers()
        
        if len(online_servers) == 0:
            logger.error("No storage servers online")
            return {'status': 'ERROR', 'message': 'No storage servers available'}
        
        logger.info(f"Upload request for {filename} ({file_size} bytes, {n} chunks)")
        logger.info(f"Replication factor: 3, Online servers: {len(online_servers)}")
        aloc = []
        
        for chunk_id in range(n):
            replica_servers = self.select_replica_servers(3)
            
            if len(replica_servers) == 0:
                logger.error("No servers available for chunk allocation")
                return {'status': 'ERROR', 'message': 'No servers available'}
            
            aloc.append({'chunk_id': chunk_id,'replicas': replica_servers})
            replica_ids = [s['id'] for s in replica_servers]
            logger.info(f"  Chunk {chunk_id} -> Primary: {replica_ids[0]}, Replicas: {replica_ids[1:] if len(replica_ids) > 1 else 'none'}")
        
        return {'status': 'SUCCESS','chunk_allocations': aloc}
    
    def handle_complete(self, request):
        filename = request['filename']
        chunks = request['chunks']
        total_size = request['total_size']
        
        with self.lock:
            self.files[filename] = {'chunks': chunks,'total_size': total_size,'upload_time': datetime.now().isoformat()}
        
        logger.info(f"Upload complete for {filename}")
        logger.info(f"  Total chunks: {len(chunks)}, Total size: {total_size} bytes")
        
        for chunk in chunks:
            replica_ids = [r['server_id'] for r in chunk['replicas']]
            logger.info(f"  Chunk {chunk['chunk_id']}: {len(chunk['replicas'])} replicas on {replica_ids}")
        
        return {'status': 'SUCCESS', 'message': 'File registered successfully'}
    
    def handle_download(self, request):
        filename = request['filename']
        
        with self.lock:
            if filename not in self.files:
                logger.warning(f"Download request for non-existent file: {filename}")
                return {'status': 'ERROR', 'message': 'File not found'}
            
            file_info = self.files[filename]
        
        logger.info(f"Download request for {filename} - {len(file_info['chunks'])} chunks")
        
        chunks_with_online_replicas = []
        for chunk in file_info['chunks']:
            online_replicas = []
            offline_count = 0
            
            for replica in chunk['replicas']:
                server_id = replica['server_id']
                with self.lock:
                    if self.server_health[server_id]['status'] == 'online':
                        online_replicas.append(replica)
                    else:
                        offline_count += 1
            
            if len(online_replicas) == 0:
                logger.error(f"No online replicas for chunk {chunk['chunk_id']}")
                return {'status': 'ERROR','message': f"Chunk {chunk['chunk_id']} has no available replicas"}
            
            logger.info(f"  Chunk {chunk['chunk_id']}: {len(online_replicas)} online replicas (+ {offline_count} offline)")
            chunks_with_online_replicas.append({'chunk_id': chunk['chunk_id'],'replicas': online_replicas,'size': chunk['size']})
        
        return {'status': 'SUCCESS','chunks': chunks_with_online_replicas,'total_size': file_info['total_size']}
    
    def server_status(self):
        with self.lock:
            status = []
            for server in self.storage_servers:
                server_id = server['id']
                health = self.server_health[server_id]
                status.append({'server_id': server_id,'host': server['host'],
                    'port': server['port'],'status': health['status'],
                    'last_check': health['last_check']
                })
        
        return {'status': 'SUCCESS', 'servers': status}
    
    def list_files(self):
        with self.lock:
            file_list = []
            for filename, info in self.files.items():
                total_replicas = sum(len(chunk['replicas']) for chunk in info['chunks'])
                file_list.append({'filename': filename,'size': info['total_size'],'chunks': len(info['chunks']),'replicas': total_replicas,'upload_time': info['upload_time']})
        
        logger.info(f"List files request - {len(file_list)} files")
        return {'status': 'SUCCESS', 'files': file_list}
    
    def start(self):
        self.health_check_thread = threading.Thread(target=self.health_monitor)
        self.health_check_thread.daemon = True
        self.health_check_thread.start()
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        logger.info(f"Metadata Server started on {self.host}:{self.port}")
        logger.info(f"Managing {len(self.storage_servers)} storage servers")
        logger.info(f"Replication factor: 3")
        logger.info(f"Health check interval: {HEALTH_CHECK_INTERVAL}s")
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client,args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logger.info("Metadata Server shutting down...")
            self.running = False
        finally:
            server_socket.close()

server = MetadataServer(METADATA_SERVER_HOST, METADATA_SERVER_PORT)
server.start()

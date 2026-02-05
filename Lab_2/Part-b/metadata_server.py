import socket
import json
import threading
import logging
import random
from datetime import datetime

METADATA_SERVER_HOST = '10.81.1.104'
METADATA_SERVER_PORT = 5000
STORAGE_SERVERS = [
    {'host': '10.81.1.104', 'port': 6001, 'id': 'storage_1'},
    {'host': '10.81.1.104', 'port': 6002, 'id': 'storage_2'},
    {'host': '10.81.32.46', 'port': 6003, 'id': 'storage_3'},
    {'host': '10.81.32.46', 'port': 6004, 'id': 'storage_4'},
]
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

logging.basicConfig(
    level=getattr(logging,'INFO'),
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
        self.lock = threading.Lock()
        
    def select_repl(self, num_replicas):
        available_servers = self.storage_servers.copy()
        random.shuffle(available_servers)
        return available_servers[:num_replicas]
    
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
        num_chunks = request['num_chunks']
        
        logger.info(f"Upload request for {filename} ({file_size} bytes, {num_chunks} chunks)")
        logger.info(f"Replication factor: 3")
        
        alloc = []
        for chunk_id in range(num_chunks):
            replica_servers = self.select_repl(3)
            alloc.append({'chunk_id': chunk_id,'replicas': replica_servers})
            replica_ids = [s['id'] for s in replica_servers]
            logger.info(f"  Chunk {chunk_id} -> Primary: {replica_ids[0]}, Replicas: {replica_ids[1:]}")
        
        return {'status': 'SUCCESS','chunk_allocations': alloc}
    
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
        
        chunks_with_replicas = []
        for chunk in file_info['chunks']:
            replicas = chunk['replicas']
            logger.info(f"  Chunk {chunk['chunk_id']}: {len(replicas)} replicas available")
            chunks_with_replicas.append({'chunk_id': chunk['chunk_id'],'replicas': replicas,'size': chunk['size']})
        
        return {'status': 'SUCCESS','chunks': chunks_with_replicas,'total_size': file_info['total_size']}
    
    def list_files(self):
        with self.lock:
            file_list = []
            for filename, info in self.files.items():
                total_replicas = sum(len(chunk['replicas']) for chunk in info['chunks'])
                file_list.append({'filename': filename,'size': info['total_size'],'chunks': len(info['chunks']),'replicas': total_replicas,'upload_time': info['upload_time']})
        
        logger.info(f"List files request - {len(file_list)} files")
        return {'status': 'SUCCESS', 'files': file_list}
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        logger.info(f"Metadata Server started on {self.host}:{self.port}")
        logger.info(f"Managing {len(self.storage_servers)} storage servers")
        logger.info(f"Replication factor: {3}")
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client,args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logger.info("Metadata Server shutting down...")
        finally:
            server_socket.close()

server = MetadataServer(METADATA_SERVER_HOST, METADATA_SERVER_PORT)
server.start()

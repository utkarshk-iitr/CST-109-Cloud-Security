import socket
import json
import threading
import logging
from datetime import datetime

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
STORAGE_SERVERS = [
    {'host': '10.81.1.104', 'port': 6001, 'id': 'storage_1'},
    {'host': '10.81.1.104', 'port': 6002, 'id': 'storage_2'},
    {'host': '10.81.32.46', 'port': 6003, 'id': 'storage_3'},
    {'host': '10.81.32.46', 'port': 6004, 'id': 'storage_4'},
]
METADATA_SERVER_HOST = '10.81.1.104'
METADATA_SERVER_PORT = 5000

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
        self.index = 0
        self.lock = threading.Lock()
        
    def get_server(self):
        with self.lock:
            server = self.storage_servers[self.index]
            self.index = (self.index + 1) % len(self.storage_servers)
            return server
    
    def handle_client(self, client_socket, address):
        try:
            data = client_socket.recv(4096).decode()
            request = json.loads(data)
            
            logger.info(f"Received request from {address}: {request['operation']}")
            operation = request['operation']
            
            if operation == 'UPLOAD_REQUEST':
                response = self.handle_upload(request)
            elif operation == 'DOWNLOAD_REQUEST':
                response = self.handle_download(request)
            elif operation == 'LIST_FILES':
                response = self.list_files()
            elif operation == 'UPLOAD_COMPLETE':
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
        n = request['num_chunks']
        logger.info(f"Upload request for {filename} ({file_size} bytes, {n} chunks)")
        
        alloc = []
        for chunk_id in range(n):
            server = self.get_server()
            alloc.append({'chunk_id': chunk_id,'server': server})
            logger.info(f"  Chunk {chunk_id} -> {server['id']}")
        
        return {'status': 'SUCCESS','chunk_allocations': alloc}
    
    def handle_complete(self, request):
        filename = request['filename']
        chunks = request['chunks']
        total_size = request['total_size']
        
        with self.lock:
            self.files[filename] = {'chunks': chunks,'total_size': total_size,'upload_time': datetime.now().isoformat()}
        
        logger.info(f"Upload complete for {filename} - {len(chunks)} chunks, {total_size} bytes")
        return {'status': 'SUCCESS', 'message': 'File registered successfully'}
    
    def handle_download(self, request):
        filename = request['filename']
        
        with self.lock:
            if filename not in self.files:
                logger.warning(f"Download request for non-existent file: {filename}")
                return {'status': 'ERROR', 'message': 'File not found'}
            file_info = self.files[filename]
        
        logger.info(f"Download request for {filename} - {len(file_info['chunks'])} chunks")
        return {'status': 'SUCCESS','chunks': file_info['chunks'],'total_size': file_info['total_size']}
    
    def list_files(self):
        with self.lock:
            file_list = []
            for filename, info in self.files.items():
                file_list.append({'filename': filename,'size': info['total_size'],'chunks': len(info['chunks']),'upload_time': info['upload_time']})
        
        logger.info(f"List files request - {len(file_list)} files")
        return {'status': 'SUCCESS', 'files': file_list}
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        logger.info(f"Metadata Server started on {self.host}:{self.port}")
        logger.info(f"Managing {len(self.storage_servers)} storage servers")
        
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

server = MetadataServer(METADATA_SERVER_HOST,METADATA_SERVER_PORT)
server.start()

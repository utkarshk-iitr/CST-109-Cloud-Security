import socket
import json
import threading
import logging
import os
import sys
from datetime import datetime

LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
STORAGE_SERVERS = [
    {'host': '10.81.1.104', 'port': 6001, 'id': 'storage_1'},
    {'host': '10.81.1.104', 'port': 6002, 'id': 'storage_2'},
    {'host': '10.81.32.46', 'port': 6003, 'id': 'storage_3'},
    {'host': '10.81.32.46', 'port': 6004, 'id': 'storage_4'},
]

def setup_logging(server_id):
    logging.basicConfig(
        level=getattr(logging,"INFO"),
        format=LOG_FORMAT,
        handlers=[logging.FileHandler(f'{server_id}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),logging.StreamHandler()]
    )
    return logging.getLogger(f'StorageServer-{server_id}')


class StorageServer:
    def __init__(self, host, port, server_id):
        self.host = host
        self.port = port
        self.server_id = server_id
        self.storage_dir = f"{server_id}"
        self.logger = setup_logging(server_id)
        self.request_count = 0
        os.makedirs(self.storage_dir, exist_ok=True)
        
    def handle_client(self, client_socket, address):
        try:
            data = client_socket.recv(1024).decode()
            request = json.loads(data)
            op = request['operation']
            self.request_count += 1
            self.logger.info(f"Request #{self.request_count} from {address}: {op}")
            
            if op == 'STORE_CHUNK':
                resp = self.handle_store(client_socket, request)
            elif op == 'RETRIEVE_CHUNK':
                resp = self.handle_retrieve(client_socket, request)
            else:
                resp = {'status': 'ERROR', 'message': 'Unknown operation'}
                client_socket.send(json.dumps(resp).encode())
            
        except Exception as e:
            self.logger.error(f"Error handling client {address}: {e}")
            error_response = {'status': 'ERROR', 'message': str(e)}
            try:
                client_socket.send(json.dumps(error_response).encode())
            except:
                pass
        finally:
            client_socket.close()
    
    def handle_store(self, client_socket, request):
        filename = request['filename']
        chunk_id = request['chunk_id']
        chunk_size = request['chunk_size']
        client_socket.send(b'READY')
        
        chunk_data = b''
        remaining = chunk_size
        while remaining > 0:
            data = client_socket.recv(min(remaining,8192))
            if not data: break
            chunk_data += data
            remaining -= len(data)
        chunk_filename = f"{filename}_chunk_{chunk_id}"
        chunk_path = os.path.join(self.storage_dir, chunk_filename)
        
        with open(chunk_path,'wb') as f:
            f.write(chunk_data)
        
        self.logger.info(f"Stored chunk {chunk_id} of {filename} ({len(chunk_data)} bytes)")
        resp = {'status': 'SUCCESS','message': 'Chunk stored successfully','chunk_id': chunk_id}
        client_socket.send(json.dumps(resp).encode())
        return resp
    
    def handle_retrieve(self, client_socket, request):
        filename = request['filename']
        chunk_id = request['chunk_id']
        chunk_filename = f"{filename}_chunk_{chunk_id}"
        chunk_path = os.path.join(self.storage_dir, chunk_filename)
        
        if not os.path.exists(chunk_path):
            self.logger.error(f"Chunk {chunk_id} of {filename} not found")
            response = {'status': 'ERROR', 'message': 'Chunk not found'}
            client_socket.send(json.dumps(response).encode())
            return response
        
        chunk_size = os.path.getsize(chunk_path)
        response = {'status': 'SUCCESS','chunk_size': chunk_size}
        client_socket.send(json.dumps(response).encode())
        client_socket.recv(1024)
        
        with open(chunk_path,'rb') as f:
            while True:
                data = f.read(8192)
                if not data: break
                client_socket.send(data)
        
        self.logger.info(f"Sent chunk {chunk_id} of {filename} ({chunk_size} bytes)")
        return response
    
    def start(self):
        server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server_socket.bind((self.host,self.port))
        server_socket.listen(5)
        self.logger.info(f"Storage Server '{self.server_id}' started on {self.host}:{self.port}")
        self.logger.info(f"Storage directory: {self.storage_dir}")
        
        try:
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client,args=(client_socket, address))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            self.logger.info(f"Storage Server '{self.server_id}' shutting down...")
            self.logger.info(f"Total requests served: {self.request_count}")
        finally:
            server_socket.close()

if len(sys.argv)!=2:
    print("Usage: python3 storage_server.py <server_number>")
    sys.exit(1)

server_num = int(sys.argv[1])
if server_num<1 or server_num>4:
    print(f"Server number must be between 1 and 4")
    sys.exit(1)

server_config = STORAGE_SERVERS[server_num - 1]
server = StorageServer(server_config['host'],server_config['port'],server_config['id'])
server.start()

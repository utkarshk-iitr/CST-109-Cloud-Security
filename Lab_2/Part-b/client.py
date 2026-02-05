import socket
import json
import os
import math
import random

METADATA_SERVER_HOST = '10.81.1.104'
METADATA_SERVER_PORT = 5000
CHUNK_SIZE = 1024*1024

class DFSClient:
    def __init__(self):
        self.metadata_host = METADATA_SERVER_HOST
        self.metadata_port = METADATA_SERVER_PORT
        
    def connect_metadata(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.metadata_host, self.metadata_port))
        return sock
    
    def connect_storage(self, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return sock
    
    def upload_file(self, filepath):
        if not os.path.exists(filepath):
            print(f"Error: File {filepath} not found")
            return False
        
        filename = os.path.basename(filepath)
        file_size = os.path.getsize(filepath)
        n = math.ceil(file_size/CHUNK_SIZE)
        
        print(f"\n{'='*70}")
        print(f"Uploading: {filename}")
        print(f"Size: {file_size} bytes ({file_size / (1024*1024):.2f} MB)")
        print(f"Chunks: {n}")
        print(f"{'='*70}\n")
        
        try:
            sock = self.connect_metadata()
            request = {'operation': 'UPLOAD_REQUEST','filename': filename,'file_size': file_size,'num_chunks': n}
            sock.send(json.dumps(request).encode())
            response = json.loads(sock.recv(4096).decode())
            sock.close()
            
            if response['status'] != 'SUCCESS':
                print(f"Error: {response['message']}")
                return False
            
        except Exception as e:
            print(f"Error connecting to metadata server: {e}")
            return False
        
        chunks_info = []
        with open(filepath,'rb') as f:
            for allocation in response['chunk_allocations']:
                chunk_id = allocation['chunk_id']
                replica_servers = allocation['replicas']
                
                chunk_data = f.read(CHUNK_SIZE)
                chunk_size = len(chunk_data)
                print(f"\nChunk {chunk_id} ({chunk_size} bytes):")
                
                repl = []
                for idx, server in enumerate(replica_servers):
                    is_primary = (idx == 0)
                    replica_label = "PRIMARY" if is_primary else f"REPLICA-{idx}"
                    try:
                        storage_sock = self.connect_storage(server['host'], server['port'])
                        request = {'operation': 'STORE_CHUNK','filename': filename,'chunk_id': chunk_id,'chunk_size': chunk_size,'is_replica': not is_primary}
                        storage_sock.send(json.dumps(request).encode())
                        
                        storage_sock.recv(1024)
                        storage_sock.sendall(chunk_data)
                        response = json.loads(storage_sock.recv(1024).decode())
                        storage_sock.close()
                        
                        if response['status'] == 'SUCCESS':
                            print(f" {replica_label} -> {server['id']}")
                            repl.append({'server_id': server['id'],'server_host': server['host'],'server_port': server['port'],'is_primary': is_primary})
                        else:
                            print(f" {replica_label} -> {server['id']}: {response['message']}")
                            
                    except Exception as e:
                        print(f" {replica_label} -> {server['id']}: {e}")
                
                if len(repl) == 0:
                    print(f"\n Failed to store chunk {chunk_id} on any server")
                    return False
                
                chunks_info.append({'chunk_id': chunk_id,'replicas': repl,'size': chunk_size})
        try:
            sock = self.connect_metadata()
            request = {'operation': 'UPLOAD_COMPLETE','filename': filename,'chunks': chunks_info,'total_size': file_size}
            sock.send(json.dumps(request).encode())
            response = json.loads(sock.recv(4096).decode())
            sock.close()
            
            if response['status'] == 'SUCCESS':
                print(f"\nUpload complete: {filename}")
                total_replicas = sum(len(chunk['replicas']) for chunk in chunks_info)
                print(f"  Total chunks: {len(chunks_info)}")
                print(f"  Total replicas created: {total_replicas}")
                return True
            else:
                print(f"\n Error registering file: {response['message']}")
                return False
                
        except Exception as e:
            print(f"\n Error notifying metadata server: {e}")
            return False
    
    def download_file(self, filename, output_path=None):
        if output_path is None:
            output_path = f"downloaded_{filename}"
        print(f"Downloading: {filename}")
        
        try:
            sock = self.connect_metadata()
            request = {'operation': 'DOWNLOAD_REQUEST','filename': filename}
            sock.send(json.dumps(request).encode())
            response = json.loads(sock.recv(8192).decode())
            sock.close()
            
            if response['status'] != 'SUCCESS':
                print(f"Error: {response['message']}")
                return False
            
            chunks = response['chunks']
            total_size = response['total_size']
            print(f"File size: {total_size} bytes ({total_size / (1024*1024):.2f} MB)")
            print(f"Chunks: {len(chunks)}\n")
            
        except Exception as e:
            print(f"Error connecting to metadata server: {e}")
            return False
        
        with open(output_path,'wb') as f:
            for chunk_info in sorted(chunks, key=lambda x: x['chunk_id']):
                chunk_id = chunk_info['chunk_id']
                replicas = chunk_info['replicas']
                chunk_size = chunk_info['size']
                
                print(f"Chunk {chunk_id} ({chunk_size} bytes): {len(replicas)} replicas available")
                random.shuffle(replicas)
                chunk_downloaded = False
                
                for replica in replicas:
                    server_host = replica['server_host']
                    server_port = replica['server_port']
                    server_id = replica['server_id']
                    
                    try:
                        storage_sock = self.connect_storage(server_host, server_port)
                        request = {'operation': 'RETRIEVE_CHUNK','filename': filename,'chunk_id': chunk_id}
                        storage_sock.send(json.dumps(request).encode())
                        response = json.loads(storage_sock.recv(1024).decode())
                        
                        if response['status'] != 'SUCCESS':
                            print(f" {server_id}: {response['message']}")
                            storage_sock.close()
                            continue
                        
                        rec_chunk_size = response['chunk_size']
                        storage_sock.send(b'READY')
                        
                        chunk_data = b''
                        remaining = rec_chunk_size
                        while remaining > 0:
                            data = storage_sock.recv(min(remaining, 8192))
                            if not data: break
                            chunk_data += data
                            remaining -= len(data)
                        
                        storage_sock.close()
                        f.write(chunk_data)
                        print(f"Downloaded from {server_id}")
                        chunk_downloaded = True
                        break
                        
                    except Exception as e:
                        print(f" {server_id}: {e}")
                        continue
                
                if not chunk_downloaded:
                    print(f"\n Failed to download chunk {chunk_id} from any replica")
                    return False
        
        print(f"\nDownload complete: {output_path}")
        return True
    
    def list_files(self):
        try:
            sock = self.connect_metadata()
            request = {'operation': 'LIST_FILES'}
            sock.send(json.dumps(request).encode())
            response = json.loads(sock.recv(8192).decode())
            sock.close()
            
            if response['status'] != 'SUCCESS':
                print(f"Error: {response['message']}")
                return
            
            files = response['files']
            
            if not files:
                print("\nNo files in the system")
                return
            
            print(f"\n{'='*90}")
            print(f"Files in Distributed File System ({len(files)} files)\n")
            print(f"{'Filename':<30} {'Size (MB)':<12} {'Chunks':<10} {'Replicas':<10} {'Upload Time':<18}")
            print(f"{'-'*90}")
            
            for file_info in files:
                size_mb = file_info['size'] / (1024 * 1024)
                upload_time = file_info['upload_time'][:19]
                print(f"{file_info['filename']:<30} {size_mb:<12.2f} {file_info['chunks']:<10} {file_info['replicas']:<10} {upload_time:<18}")
            
            print(f"{'='*90}\n")
            
        except Exception as e:
            print(f"Error listing files: {e}")


def print_menu():
    print("\n" + "="*70)
    print("Distributed File System Client (With Replication)\n")
    print("1. Upload file")
    print("2. Download file")
    print("3. List files")
    print("4. Exit")
    print("="*70)

client = DFSClient()

while True:
    print_menu()
    choice = input("Enter your choice (1-4): ").strip()
    
    if choice == '1':
        filepath = input("Enter file path to upload: ").strip()
        client.upload_file(filepath)
        
    elif choice == '2':
        filename = input("Enter filename to download: ").strip()
        output_path = input("Enter output path (press Enter for default): ").strip()
        if not output_path: output_path = None
        client.download_file(filename, output_path)
        
    elif choice == '3':
        client.list_files()
        
    elif choice == '4':
        print("\nExiting...")
        break

    else:
        print("Invalid choice. Please try again.")

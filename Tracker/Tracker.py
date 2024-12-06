import socket
import threading
import random
import sys
import os
from Bitfield import Bitfield
from urllib.parse import urlparse
from tabulate import tabulate
class Tracker:
    def __init__(self, ip, port):
        self.progress: dict[str, list[tuple[str, Bitfield]]] = {}
        self.peers: dict[str, tuple[str, str]] = {}
        self.progress_lock = threading.Lock()
        self.peer_lock = threading.Lock()
        self.ip = ip
        self.port = port
        self.server_thread = threading.Thread(target=self.start_socket, daemon=True)
        self.server_thread.start()
    
    def start_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, self.port))
        self.socket.listen(10)
        while True:
            conn, addr = self.socket.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()        
    def listen_for_commands(self):
        while True:
            command = input()
            if command == 'print':
                self.print()
            elif command == 'exit':
                self.socket.close()
                sys.exit(0)
            else:
                print('Invalid command')
    def handle_client(self, conn: socket.socket, addr: tuple[str, int]):
        try:
            data = conn.recv(1024).decode('utf-8')
            self.write_log("Received:", data)
            messages = self.parse_message(data)
            print("Messages:", messages)
            for message  in messages:
                if message.startswith('register:'):
                    _, port, id = message.split(':')
                    ip = addr[0]
                    with self.peer_lock:
                        existing_id = None
                        for peer_id, (peer_ip, peer_port) in self.peers.items():
                            if peer_ip == ip and peer_port == port:
                                existing_id = peer_id
                                break
                        if existing_id:
                            del self.peers[existing_id]
                        self.peers[id] = (ip, port)
                    
                    self.write_log(f'Registered {id} with {ip}:{port}')
                    conn.sendall(b'Registered')

                elif message.startswith('upload:'):
                    _, info_hash, piece_count, id = message.split(':')
                    piece_count = int(piece_count)
                    with self.progress_lock:
                        self.progress[info_hash] = [(id, Bitfield(piece_count, True))]
                    with self.peer_lock:
                        ip, port = self.peers[id]
                    
                    self.distribute_torrent(info_hash, piece_count, (id, ip, port))
                    self.write_log(f'Uploaded {info_hash} with {piece_count} pieces')
                    conn.sendall(f'Upload {info_hash} success'.encode('utf-8'))

                elif message.startswith('get:'):
                    _, info_hash = message.split(':')
                    result = self.getPeerInfo(info_hash)
                    self.write_log(f'Getting {info_hash} info', str(result))
                    conn.sendall((str(result)+"\n").encode('utf-8'))

                elif message.startswith('downloaded:'):
                    _, info_hash, piece_index, id, piece_count = message.split(':')
                    piece_index = int(piece_index)
                    piece_count = int(piece_count)
                    found = False
                    with self.progress_lock:
                        progress = self.progress[info_hash]
                        for (peer_id, peer_progress) in progress:
                            if peer_id == id:
                                found = True
                                peer_progress.set_piece(piece_index)
                                break
                        if not found:
                            array = Bitfield(piece_count)
                            array.set_piece(piece_index)
                            progress.append((id, array))
                    conn.sendall(f'Progress of {info_hash} piece {piece_index} updated'.encode('utf-8'))
                elif message.startswith('unregister:'):
                    _, id = message.split(':')
                    with self.peer_lock:
                        self.peers.pop(id)
                    self.write_log(f'Unregistered {id}')       
                    conn.sendall(b'Unregistered')
                elif message == '':
                    pass
                else:
                    conn.sendall(b'Invalid request')
                    self.write_log('Invalid request', message)
        except Exception as e:
            raise e
        finally:
            conn.close()
    def distribute_torrent(self, info_hash: str, piece_count: int, owner: tuple[str, str, int]):
        peers = self.select_random_peers()
        self.write_log(f'Distributing {info_hash} to {peers}')
        for peer in peers:
            peer_id, peer_ip, peer_port = peer
            if peer_id == owner[0]:
                continue
            pieces = self.random_pieces(piece_count)
            for piece in pieces:
                threading.Thread(target=self.send_data, args=((peer_ip, int(peer_port)), \
                                    f'tracker:{info_hash}:{owner[1]}:{owner[2]}:{piece}:{piece_count}')).start()
    def random_pieces(self, piece_count: int) -> list[int]:
        return random.sample(range(piece_count), min(5, piece_count))
    def select_random_peers(self) -> list[tuple[str, str,str]]:
        with self.peer_lock:
            peer_ids = list(self.peers.keys())
            chosen_ids = random.sample(peer_ids, min(5, len(peer_ids)))
            return [(id, self.peers[id][0], self.peers[id][1]) for id in chosen_ids]
    def getPeerInfo(self, info_hash: str) -> list[tuple[str, str, str, list[int]]]:
        peers = self.progress[info_hash]
        result = []
        for peer in peers:
            id, progress = peer
            with self.peer_lock:
                ip, port = self.peers[id]
            result.append((id, ip, port, progress.to_bytes()))
        return result
    
    def parse_message(self, data: str):
        return data.split("\n")

    def send_data(self, destination: tuple[str, int], data: str):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            self.write_log(f'Connecting to {destination}')
            s.connect(destination)
            data += '\n'
            s.sendall(data.encode('utf-8'))
            self.write_log("Response", s.recv(1024).decode('utf-8'))
    def write_log(self, *data: str):
        with open('/data/tracker.log', 'a') as f:
            for d in data:
                f.write(d+'')
            f.write('\n')
            
    def print(self):
        headers = ["Info Hash", "Peer ID", "IP", "Port", "Progress"]
        table = []
        with self.progress_lock and self.peer_lock:
            info_hashes = list(self.progress.keys())
            for i, info_hash in enumerate(info_hashes):
                peers = self.progress[info_hash]
                first_row = True
                max_len = 0
                for peer_id, bitfield in peers:
                    ip, port = self.peers[peer_id]
                    if len(str(bitfield)) > max_len:
                        max_len = len(str(bitfield))
                    if first_row:
                        table.append([info_hash, peer_id, ip, port, str(bitfield)])
                        first_row = False
                    else:
                        table.append(["", peer_id, ip, port, str(bitfield)])
                if i < len(info_hashes) - 1:
                    table.append(["-"*len(info_hash), "-"*len(peer_id), "-"*len(ip), "-"*len(port), "-"*max_len])
                    
        print(tabulate(table, headers=headers, tablefmt='pretty'))

        

if __name__ == '__main__':
    url = os.getenv('TRACKER_URL')
    ip, port = "0.0.0.0", 5000
    if url is not None:
        parsed = urlparse(url)
        ip = parsed.hostname
        port = parsed.port
    
    tracker = Tracker(ip, port)
    print(f'Tracker started on {ip}:{port}')
    tracker.listen_for_commands()
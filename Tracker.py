# progress = {
#     info_ hash: [(id, [])]
# }
import socket
import threading
import random

class Tracker:
    def __init__(self, ip, port):
        self.progress: dict[str, list[tuple[str, list[int]]]] = {}
        self.peers: dict[str, tuple[str, str]] = {}
        self.progress_lock = threading.Lock()
        self.peer_lock = threading.Lock()
        self.ip = ip
        self.port = port
    def start_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, self.port))
        self.socket.listen(10)
        while True:
            conn, addr = self.socket.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()        
    def handle_client(self, conn: socket.socket, addr: tuple[str, int]):
        try:
            data = conn.recv(1024).decode('utf-8')
            print("Received:", data)
            messages = self.parse_message(data)
            print("Messages:", messages)
            for message in messages:
                if message.startswith('register:'):
                    _, ip, port, id = message.split(':')
                    with self.peer_lock:
                        self.peers[id] = (ip, port)
                    print(f'Registered {id} with {ip}:{port}')
                    conn.sendall(b'Registered')

                elif message.startswith('upload:'):
                    _, info_hash, piece_count, id = message.split(':')
                    piece_count = int(piece_count)
                    with self.progress_lock:
                        self.progress[info_hash] = [(id, [1]*piece_count)]
                    with self.peer_lock:
                        ip, port = self.peers[id]
                    
                    self.distribute_torrent(info_hash, piece_count, (id, ip, port))
                    print(f'Uploaded {info_hash} with {piece_count} pieces')
                    conn.sendall(b'Upload success')

                elif message.startswith('get:'):
                    _, info_hash = message.split(':')
                    result = self.getPeerInfo(info_hash)
                    print(f'Getting {info_hash} info')
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
                                peer_progress[piece_index] = 1
                                break
                        if not found:
                            array = [0]*piece_count
                            array[piece_index] = 1
                            progress.append((id, array))
                    conn.sendall(b'Progress updated')
                elif message.startswith('unregister:'):
                    _, id = message.split(':')
                    with self.peer_lock:
                        self.peers.pop(id)
                    conn.sendall(b'Unregistered')
                elif message == '':
                    pass
                else:
                    conn.sendall(b'Invalid request')
                    print('Invalid request', message)
        except Exception as e:
            raise e
        finally:
            conn.close()
    def distribute_torrent(self, info_hash: str, piece_count: int, owner: tuple[str, str, int]):
        peers = self.select_random_peers()
        print(f'Distributing {info_hash} to {peers}')
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
            result.append((id, ip, port, progress))
        return result
    
    def parse_message(self, data: str):
        return data.split("\n")

    def send_data(self, destination: tuple[str, int], data: str):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f'Connecting to {destination}')
            s.connect(destination)
            data += '\n'
            s.sendall(data.encode('utf-8'))
            print("Response", s.recv(1024).decode('utf-8'))

if __name__ == '__main__':
    tracker = Tracker("localhost", 5000)

    print('Tracker started')
    tracker.start_socket()
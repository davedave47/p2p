from constants import PIECE_SIZE, TRACKER_IP, TRACKER_PORT
import socket
import threading
import shlex
import os
import uuid
import Metainfo
import argparse
import random
import signal
from Bitfield import Bitfield
class Peer:
    def __init__(self, ip: str, port: str):
        self.ip = ip
        self.port = port
        self.server_thread = threading.Thread(target=self.start_socket, daemon=True)
        self.id = uuid.uuid4()
        self.progress: dict[str, Bitfield] = {}
        self.progress_lock = threading.Lock()
        self.log_lock = threading.Lock()
        tracker_ip, tracker_port = self.find_tracker()
        self.register(tracker_ip, tracker_port)
        self.server_thread.start()
        signal.signal(signal.SIGINT, self.signal_handler)
    def signal_handler(self, sig, frame):
        self.write_logs("socket", "Exiting...")
        tracker_ip, tracker_port = self.find_tracker()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((tracker_ip, tracker_port))
            s.sendall(f'unregister:{self.id}'.encode('utf-8'))
            self.write_logs('socket', s.recv(1024).decode('utf-8') )
        self.socket.close()
        os._exit(0)

    def register(self, tracker_ip: str, tracker_port: int):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((tracker_ip, tracker_port))
            s.sendall(f'register:{self.ip}:{self.port}:{self.id}'.encode('utf-8'))
            self.write_logs('socket',s.recv(1024).decode('utf-8'))

    def start_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.ip, self.port))
        self.socket.listen(10)
        while True:
            try:
                conn, addr = self.socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr)).start()
            except Exception as e:
                break

    def handle_client(self, conn: socket.socket, addr: tuple[str, int]):
        try:
            data = conn.recv(1024).decode('utf-8')
            self.write_logs("socket", "Received:", data)
            messages = self.parse_message(data)
            for message in messages:
                if message.startswith('tracker:'):
                    _, info_hash, peer_ip, peer_port, piece_index, piece_count = message.split(':')
                    tracker_ip, tracker_port = self.find_tracker()
                    threading.Thread(target=self.download_from_peer, args=((peer_ip, int(peer_port)), [int(piece_index)], (tracker_ip, tracker_port), info_hash, int(piece_count))).start()
                    #threading.Thread(target=self.download_piece, args=((tracker_ip, int(tracker_port)), info_hash, int(piece_count), int(piece_index), (peer_ip, int(peer_port)))).start()
                elif message.startswith('peer:'):
                    _, info_hash, piece_index = message.split(':')
                    conn.sendall(self.get_piece(info_hash, piece_index))
                    self.write_logs("socket", f"Sent piece {piece_index} of {info_hash} to {addr}")
                elif message == "":
                    pass
                else:
                    conn.sendall(b'Invalid request')
                    self.write_logs("socket", 'Invalid request', message)
        except Exception as e:
            raise e
        finally:
            conn.close()
        
    def split_file(self, file: str, starting_piece: int, location: str) -> int:
        if not os.path.exists(location):
            os.makedirs(location)
        with open(file, 'rb') as f:
            while True:
                piece = f.read(PIECE_SIZE)
                if not piece:
                    break
                if len(piece) < PIECE_SIZE:
                    piece += b'\0' * (PIECE_SIZE - len(piece))
                piece_path = os.path.join(location, f'{starting_piece}')
                with open(piece_path, 'wb') as piece_file:
                    piece_file.write(piece)
                starting_piece += 1
        return starting_piece
    def get_piece(self, info_hash: str, piece_index: str) -> bytes:
        piece_path = f'./files/{info_hash}/{piece_index}'
        with open(piece_path, 'rb') as f:
            return f.read()
    def find_tracker(self) -> tuple[str, int]:
        return (TRACKER_IP, TRACKER_PORT)
    def listen_for_commands(self):
        while True:
            print("Enter a command:")
            command = input()
            args = shlex.split(command)
            if args[0] == 'exit':
                break
            elif args[0] == 'upload':
                if len(args) < 3:
                    print("Usage: upload <name> <files>")
                    continue
                name = args[1]
                files = args[2:]
                threading.Thread(target = self.upload, args=(name,files)).start()
            elif args[0] == 'download':
                torrents = args[1:]
                for torrent in torrents:
                    threading.Thread(target=self.download, args=(torrent,)).start()
            else:
                print("Invalid command")
    def upload(self, name, files: list[str]):
        tracker_ip, tracker_port = self.find_tracker()
        metainfo = Metainfo.Metainfo(f'{tracker_ip}:{tracker_port}', name, *files)
        try:
            metainfo.write()
        except FileExistsError as e:
            print(e)
            return
        starting_piece = 0
        for file in files:
            starting_piece = self.split_file(file, starting_piece, f'./files/{metainfo.info_hash.hex()}')
        self.progress[metainfo.info_hash.hex()] = Bitfield(metainfo.piece_count, True)

        # Send metainfo to tracker
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((tracker_ip, tracker_port))
            s.sendall(f'upload:{metainfo.info_hash.hex()}:{metainfo.piece_count}:{self.id}\n'.encode('utf-8'))
            self.write_logs("socket",s.recv(1024).decode('utf-8'))

    def download(self, torrent: str):
        metainfo = Metainfo.Metainfo(torrent)
        # Get peer from tracker
        tracker_ip, tracker_port = metainfo.tracker_url.split(':')
        tracker_port = int(tracker_port)
       
        progress = self.progress[metainfo.info_hash.hex()]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((tracker_ip, tracker_port))
            s.sendall(f'get:{metainfo.info_hash.hex()}\n'.encode('utf-8'))
            data = self.receive_all(s).decode('utf-8')
            peers: list[tuple[str, str, str, bytes]] = eval(data)
            peers = [(peer_id, ip, port, Bitfield.from_bytes(bitfield_bytes)) for peer_id, ip, port, bitfield_bytes in peers]

        pieces_selection = self.select_pieces(peers, metainfo.piece_count)
        self.write_logs("download", f"Selected pieces: {str(pieces_selection)}")
        download_threads: list[threading.Thread] = []    
        for ip, port, pieces in pieces_selection:
            thread = threading.Thread(target=self.download_from_peer, args=((ip, int(port)), pieces, (tracker_ip, tracker_port), metainfo.info_hash.hex(), metainfo.piece_count))
            thread.start()
            download_threads.append(thread)

            # for piece in range(metainfo.piece_count):
            #     if not progress.has_piece(piece):
            #         ip, port = self.find_peer(peers, piece)
            #         thread = threading.Thread(target=self.download_piece, args=((tracker_ip, tracker_port), metainfo.info_hash.hex(), metainfo.piece_count, piece, (ip, int(port))))
            #         thread.start()
            #         download_threads.append(thread)

        for thread in download_threads:
            thread.join()   
        if progress.finished():
            self.write_logs("download", f"Download {metainfo.info_hash.hex()} complete")
            self.merge_files(metainfo)
            return
        else:
            self.write_logs("download", f"Download {metainfo.info_hash.hex()} unsuccessful")
            print(f"Download {metainfo.name}.torrent unsuccessful try again")

    def receive_all(self, sock: socket.socket) -> bytes:
        data = b''
        while True:
            part = sock.recv(1024)
            if not part:
                break
            data += part
            if '\n'.encode('utf-8') in part:
                break
        return data
            
    def merge_files(self, metainfo: Metainfo.Metainfo):
        destination = f'./download/{metainfo.info_hash.hex()}'
        os.makedirs(destination, exist_ok=True)
        starting_piece = 0
        for file in metainfo.files:
            read_length = 0
            with open(f'{destination}/{file.getName()}', 'wb') as f:
                for piece in range(starting_piece, metainfo.piece_count):
                    piece_path = f'./files/{metainfo.info_hash.hex()}/{piece}'
                    with open(piece_path, 'rb') as piece_file:
                        data = piece_file.read()
                        if read_length + len(data) > file.length:
                            data = data[:file.length - read_length]
                        f.write(data)
                        starting_piece += 1
                        read_length += len(data)
                    if read_length >= file.length:
                        break
        print(f"Downloaded {metainfo.name}.torrent to {destination}")
        
    def select_pieces(self, peers: list[tuple[str, str, str, Bitfield]], piece_count: int) -> list[tuple[str, str, list[int]]]:
        # Sort peers by their Bitfield.get_progress() in ascending order
        sorted_peers = sorted(peers, key=lambda x: x[3].get_progress())
        
        pieces_selection: list[tuple[str, str, list[int]]] = []
        for piece in range(piece_count):
            for peer in sorted_peers:
                id, ip, port, bitfield = peer
                if id != str(self.id) and bitfield.has_piece(piece):
                    found = False
                    for selection in pieces_selection:
                        if selection[0] == ip and selection[1] == port:
                            selection[2].append(piece)
                            found = True
                            break
                    if not found:
                        pieces_selection.append((ip, port, [piece]))
                    break
        
        return pieces_selection
                    
        
    def download_from_peer(self, peer: tuple[str, int], pieces, tracker: tuple[str, int], info_hash: str, piece_count: int):
        download_threads: list[threading.Thread] = []
        for piece in pieces:
            thread = threading.Thread(target=self.download_piece, args=(tracker, info_hash, piece_count, piece, peer))
            thread.start()
            download_threads.append(thread)
        for thread in download_threads:
            thread.join()    
    
    def download_piece(self, tracker: tuple[str,int], info_hash: str, piece_count:int,  piece: int, peer: tuple[str, int]):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(peer)
            s.sendall(f'peer:{info_hash}:{piece}\n'.encode('utf-8'))
            location = f'./files/{info_hash}'
            os.makedirs(location, exist_ok=True)
            self.write_logs("download", f"Downloading piece {piece} of {info_hash} from ip {peer[0]} and port {peer[1]}")
            with open(f'{location}/{piece}', 'wb') as f:
                while True:
                    data = s.recv(PIECE_SIZE)
                    if not data:
                        break
                    f.write(data)
            with self.progress_lock:
                if info_hash not in self.progress:
                    self.progress[info_hash] = Bitfield(piece_count)
                self.progress[info_hash].set_piece(piece)
            
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(tracker)
            s.sendall(f'downloaded:{info_hash}:{piece}:{self.id}:{piece_count}\n'.encode('utf-8'))
            self.write_logs("socket", s.recv(1024).decode('utf-8'))
    

    def find_peer(self, peers: list[tuple[str, str, str, Bitfield]], piece_index):
        while True:
            index = random.randint(0, len(peers)-1)
            peer = peers[index]
            if peer[0] != self.id and peer[3].has_piece(piece_index):
                return peer[1], peer[2]
            
    def parse_message(self, data: str):
        return data.split('\n')
    
    def write_logs(self, type: str, *data: str):
        with self.log_lock:
            path = f'./logs'
            os.makedirs(path, exist_ok=True)
            with open(f'{path}/{type}.log', 'a') as f:
                for item in data:
                    f.write(item+' ')
                f.write('\n')

            
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Peer-to-Peer File Sharing")
    parser.add_argument("ip", type=str, help="IP address of the peer")
    parser.add_argument("port", type=int, help="Port number of the peer")
    args = parser.parse_args()
    peer = Peer(args.ip, args.port)
    peer.listen_for_commands()
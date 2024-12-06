import os
import hashlib
import bencodepy
from constants import PIECE_SIZE

class File:
    def __init__(self, path, length=None):
        self.path = path
        if length is None:
            self.length = os.path.getsize(path)
        else:
            self.length = length

    def get_path_str(self):
        return self.path

    def get_path_arr(self):
        return self.path.split('/')
    def getName(self):
        return self.path.split('/')[-1]

class Metainfo:
    def __init__(self, arg1: str, arg2: str=None, *paths: str):
        if not paths and arg2 is None:
            with open(arg1, 'rb') as f:
                data = bencodepy.decode(f.read())
            self.tracker_url = data[b'announce'].decode('utf-8')
            info = data[b'info']
            self.name = info[b'name'].decode('utf-8')
            self.piece_count = info[b'pieces']
            self.files = [File('/'.join([p.decode('utf-8') for p in f[b'path']]), f[b'length']) for f in info[b'files']]
            self.info_hash = hashlib.sha1(bencodepy.encode(info)).digest()
        else:
            if not paths:
                raise ValueError("No file specified")
            self.tracker_url = arg1
            self.name = arg2
            self.files = [File(path) for path in paths]
            self.piece_count = sum((file.length + PIECE_SIZE - 1) // PIECE_SIZE for file in self.files)
            self.info_hash = hashlib.sha1(bencodepy.encode(self.get_info())).digest()

    def write(self, path: str=None):
        if path is None:
            path = './torrents'
        os.makedirs(path, exist_ok=True)
        path = os.path.join(path, f'{self.name}.torrent')
        if os.path.exists(path):
            raise FileExistsError(f"A torrent with the name '{self.name}' already exists.")
        data = {
            b'announce': self.tracker_url.encode('utf-8'),
            b'info': self.get_info()
        }

        with open(path, 'wb') as f:
            f.write(bencodepy.encode(data))

    def get_info(self):
        return {
            b'name': self.name.encode('utf-8'),
            b'piece length': PIECE_SIZE,
            b'pieces': self.piece_count,
            b'files': [{b'length': file.length, b'path': [p.encode('utf-8') for p in file.get_path_arr()]} for file in self.files]
        }
    def compare_info_hash(self, other: bytes):
        return self.info_hash == other.info_hash
    def print(self):
        print(f'Tracker URL: {self.tracker_url}')
        print(f'Torrent Name: {self.name}')
        print(f'Piece Count: {self.piece_count}')
        print(f'Info Hash: {self.info_hash}')
        print('Files:')
        for file in self.files:
            print(f'Length: {file.length}\tPath: {file.get_path_str()}')
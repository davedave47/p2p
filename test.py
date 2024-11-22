import os
def generate_file(length: int, name: str) -> str:
    with open(name, 'wb') as f:
        f.write(os.urandom(length))
    return name

def generate_peers(amount: int):
    for i in range(amount):
        folder = f'./Peer{i+1}'
        os.makedirs(folder)
        # copy constant.py, Peer.py and Metainfo.py to the peer folder
        os.system(f'cp ./Peer.py {folder}')
        os.system(f'cp ./Metainfo.py {folder}')
        os.system(f'cp ./constants.py {folder}')

generate_peers(3)
os.system('cp -r ./test ./Peer1')

# download ./test.torrent
# upload test ./test/Chapter_1_v8.0.pdf ./test/Chapter_2_v8.0.pdf ./test/Chapter_3_v8.0.pdf ./test/Chapter_4_v8.0.pdf
from bitarray import bitarray

class Bitfield:
    def __init__(self, length, fill = False):
        self.bitarray = bitarray(length)
        self.bitarray.setall(fill)
    def get_progress(self):
        return self.bitarray.count(True)
    def set_piece(self, index):
        self.bitarray[index] = True
    def has_piece(self, index):
        return self.bitarray[index]
    def to_bytes(self):
        return self.bitarray.tobytes()

    @staticmethod
    def from_bytes(data):
        bitfield = bitarray()
        bitfield.frombytes(data)
        length = len(bitfield)  
        result = Bitfield(length)
        result.bitarray = bitfield[:length]
        return result
    
    def finished(self):
        return all(self.bitarray)
    def __str__(self):
        return str(self.bitarray)
    
if __name__ == "__main__":
    test = Bitfield(10)
    test.set_piece(0)
    test.set_piece(1)
    test.set_piece(2)

    bytes = test.to_bytes()
    print(bytes)

    test2 = Bitfield.from_bytes(bytes)

    print(test2.has_piece(0))
    print(test2.has_piece(1))
    print(test2.has_piece(2))
    print(test2.has_piece(3))
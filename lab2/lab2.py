import struct
import math

class MyMD5:
    def __init__(self):
        self.state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        self.buffer = b""
        self.count = 0

        self.T = [int(4294967296 * abs(math.sin(i+1))) & 0xFFFFFFFF for i in range(64)]

    def F(self,x,y,z): return (x & y) | (~x & z)
    def G(self,x,y,z): return (x & z) | (y & ~z)
    def H(self,x,y,z): return x ^ y ^ z
    def I(self,x,y,z): return y ^ (x | ~z)

    def left_rotate(self,x,n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def process_chunk(self,chunk):
        M = list(struct.unpack("<16I",chunk))
        a, b, c, d = self.state

        for i in range(64):
            if 0 <= i <= 15:
                f = self.F(b, c, d)
                g = i
                s = [7, 12, 17, 22][i % 4]
            elif 16 <= i <= 31:
                f = self.G(b, c, d)
                g = (5*i + 1) % 16
                s = [5, 9, 14, 20][i % 4]
            elif 32 <= i <= 47:
                f = self.H(b, c, d)
                g = (3*i + 5) % 16
                s = [4, 11, 16, 23][i % 4]
            else:
                f = self.I(b, c, d)
                g = (7 * i) % 16
                s = [6, 10, 15, 21][i % 4]

            temp = (a + f + self.T[i] + M[g]) & 0xFFFFFFFF
            rotated = self.left_rotate(temp, s)
            new_b = (b + rotated) & 0xFFFFFFFF

            a, b, c, d = d, new_b, b, c

        self.state[0] = (self.state[0] + a) & 0xFFFFFFFF
        self.state[1] = (self.state[1] + b) & 0xFFFFFFFF
        self.state[2] = (self.state[2] + c) & 0xFFFFFFFF
        self.state[3] = (self.state[3] + d) & 0xFFFFFFFF

    def update(self, data):
        self.count += len(data)
        self.buffer += data
        while len(self.buffer) >= 64:
            self.process_chunk(self.buffer[:64])
            self.buffer = self.buffer[64:]

    def digest(self):
        orig_len_bits = (self.count * 8) & 0xFFFFFFFFFFFFFFFF

        self.update(b'\x80')

        while len(self.buffer) % 64 != 56:
            self.update(b'\x00')

        self.update(struct.pack("<Q", orig_len_bits))
        return "".join(format(x, '02x') for x in struct.pack("<4I", *self.state))

    @staticmethod
    def hash_string(text):
        hasher = MyMD5()
        hasher.update(text.encode('utf-8'))
        return hasher.digest()

    @staticmethod
    async def hash_upload_file(upload_file):
        hasher = MyMD5()
        while chunk := await upload_file.read(1024 * 1024):
            hasher.update(chunk)
        return hasher.digest()


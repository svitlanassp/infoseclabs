import struct
import time
from lab2.lab2 import MyMD5
from lab1.lab1 import generator

class RC5:
    def __init__(self, w=16, r=16, password=""):
        self.w = w
        self.r = r
        self.mask = (1 << w) - 1
        self.block_size = (2 * w) // 8

        self.P = 0xb7e1
        self.Q = 0x9e37

        key_bytes = self._get_rc5_key(password)
        self.S = self._key_expansion(key_bytes)

    def _get_rc5_key(self, password_phrase):
        h1 = MyMD5.hash_string(password_phrase)
        h2 = MyMD5.hash_string(h1)
        return bytes.fromhex(h2 + h1)

    def _left_rotate(self, x, y):
        y %= self.w
        return ((x << y) | (x >> (self.w - y))) & self.mask

    def _right_rotate(self, x, y):
        y %= self.w
        return ((x >> y) | (x << (self.w - y))) & self.mask

    def _key_expansion(self, user_key):
        L = list(struct.unpack("<16H", user_key))
        c = len(L)

        n_subkeys = 2 * self.r + 2
        S = [0] * n_subkeys

        S[0] = self.P
        for i in range(1, n_subkeys):
            S[i] = (S[i - 1] + self.Q) & self.mask

        t = max(c, n_subkeys)
        i = j = A = B = 0
        for _ in range(3*t):
            S[i] = self._left_rotate((S[i] + A + B) & self.mask, 3)
            A = S[i]
            i = (i + 1) % n_subkeys

            L[j] = self._left_rotate((L[j] + A + B) & self.mask, (A + B))
            B = L[j]
            j = (j + 1) % c
        return S

    def encrypt_block(self, A, B):
        A = (A + self.S[0]) & self.mask
        B = (B + self.S[1]) & self.mask
        for i in range(1, self.r + 1):
            A = (self._left_rotate(A ^ B, B) + self.S[2 * i]) & self.mask
            B = (self._left_rotate(B ^ A, A) + self.S[2 * i + 1]) & self.mask
        return A, B

    def decrypt_block(self, A, B):
        for i in range(self.r, 0, -1):
            B = self._right_rotate((B - self.S[2 * i + 1]) & self.mask, A) ^ A
            A = self._right_rotate((A - self.S[2 * i]) & self.mask, B) ^ B
        B = (B - self.S[1]) & self.mask
        A = (A - self.S[0]) & self.mask
        return A, B

    def get_initial_vector(self):
        m_val, a_val, c_val = 2 ** 28 - 1, 15 ** 3, 4181
        seed = int(time.time() * 1000000) % m_val
        nums = generator(m_val, a_val, c_val, seed, 1)
        return struct.pack('<I', nums[0])

    def pad(self, data):
        p_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([p_len] * p_len)

    def unpad(self, data):
        p_len = data[-1]
        if not (1 <= p_len <= self.block_size):
            raise ValueError("Invalid padding")
        return data[:-p_len]

    def encrypt_file(self, input_path, output_path):
        iv = self.get_initial_vector()
        iv_a, iv_b = struct.unpack("<HH", iv)

        enc_iv_a, enc_iv_b = self.encrypt_block(iv_a, iv_b)

        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            f_out.write(struct.pack("<HH", enc_iv_a, enc_iv_b))

            data = f_in.read()
            padded_data = self.pad(data)

            prev_a, prev_b = iv_a, iv_b

            for i in range(0, len(padded_data), self.block_size):
                chunk = padded_data[i:i + self.block_size]
                a, b = struct.unpack("<HH", chunk)

                a ^= prev_a
                b ^= prev_b

                enc_a, enc_b = self.encrypt_block(a, b)
                f_out.write(struct.pack("<HH", enc_a, enc_b))
                prev_a, prev_b = enc_a, enc_b

    def decrypt_file(self, input_path, output_path):
        with open(input_path, "rb") as f_in:
            enc_iv = f_in.read(self.block_size)
            if not enc_iv: return

            enc_iv_a, enc_iv_b = struct.unpack("<HH", enc_iv)
            iv_a, iv_b = self.decrypt_block(enc_iv_a, enc_iv_b)

            all_data = f_in.read()
            decrypted_chunks = []
            prev_a, prev_b = iv_a, iv_b

            for i in range(0, len(all_data), self.block_size):
                chunk = all_data[i:i + self.block_size]
                curr_enc_a, curr_enc_b = struct.unpack("<HH", chunk)

                dec_a, dec_b = self.decrypt_block(curr_enc_a, curr_enc_b)

                final_a = dec_a ^ prev_a
                final_b = dec_b ^ prev_b

                decrypted_chunks.append(struct.pack("<HH", final_a, final_b))
                prev_a, prev_b = curr_enc_a, curr_enc_b

            full_data = b"".join(decrypted_chunks)
            final_data = self.unpad(full_data)

            with open(output_path, "wb") as f_out:
                f_out.write(final_data)


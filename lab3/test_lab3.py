import unittest
import os
from lab3.lab3 import RC5

class TestRC5(unittest.TestCase):
    def setUp(self):
        self.password = "secret" #NOSONAR
        self.cipher = RC5(w=16, r=16, password=self.password)
        self.test_in = "test_input.bin"
        self.test_out = "test_output.enc"
        self.test_dec = "test_decrypted.bin"

    def tearDown(self):
        for f in [self.test_in, self.test_out, self.test_dec]:
            if os.path.exists(f):
                os.remove(f)

    def test_rotations(self):
        x = 0x1234
        rotated_l = self.cipher._left_rotate(x, 5)
        rotated_r = self.cipher._right_rotate(rotated_l, 5)
        self.assertEqual(x, rotated_r)

    def test_block_encryption_decryption(self):
        A, B = 12345, 6789
        enc_A, enc_B = self.cipher.encrypt_block(A, B)
        self.assertNotEqual((A, B), (enc_A, enc_B))

        dec_A, dec_B = self.cipher.decrypt_block(enc_A, enc_B)
        self.assertEqual((A, B), (dec_A, dec_B))

    def test_padding(self):
        data = b"Hello"
        padded = self.cipher.pad(data)
        self.assertEqual(len(padded) % self.cipher.block_size, 0)

        unpadded = self.cipher.unpad(padded)
        self.assertEqual(data, unpadded)

    def test_file_cipher_cycle(self):
        original_content = b"Test Lab 3"
        with open(self.test_in, "wb") as f:
            f.write(original_content)

        self.cipher.encrypt_file(self.test_in, self.test_out)
        self.assertTrue(os.path.exists(self.test_out))

        with open(self.test_out, "rb") as f:
            encrypted_content = f.read()
        self.assertNotEqual(original_content, encrypted_content)

        self.cipher.decrypt_file(self.test_out, self.test_dec)

        with open(self.test_dec, "rb") as f:
            decrypted_content = f.read()

        self.assertEqual(original_content, decrypted_content)

    def test_iv_uniqueness(self):
        iv1 = self.cipher.get_initial_vector()
        import time
        time.sleep(0.01)
        iv2 = self.cipher.get_initial_vector()
        self.assertNotEqual(iv1, iv2)

if __name__ == '__main__':
    unittest.main()
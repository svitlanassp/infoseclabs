import unittest
import os
import tempfile
from lab4.lab4 import RSA

class TestRSA(unittest.TestCase):
    def setUp(self):
        self.rsa = RSA(key_size=2048)

    def test_keys_generation_and_serialization(self):
        self.rsa.generate_keys()

        priv_bytes = self.rsa.get_private_key_bytes()
        pub_bytes = self.rsa.get_public_key_bytes()

        self.assertIn(b"BEGIN RSA PRIVATE KEY", priv_bytes)
        self.assertIn(b"BEGIN PUBLIC KEY", pub_bytes)

    def test_missing_keys_raise_errors(self):
        with self.assertRaises(ValueError):
            self.rsa.get_private_key_bytes()

        with self.assertRaises(ValueError):
            self.rsa.get_public_key_bytes()

        with self.assertRaises(ValueError):
            self.rsa.encrypt_file("test.txt", "out.txt")

        with self.assertRaises(ValueError):
            self.rsa.decrypt_file("test.txt", "out.txt")

    def test_key_import_export_flow(self):
        self.rsa.generate_keys()
        priv_bytes = self.rsa.get_private_key_bytes()
        pub_bytes = self.rsa.get_public_key_bytes()

        new_rsa = RSA()
        new_rsa.load_private_key(priv_bytes)
        new_rsa.load_public_key(pub_bytes)

        self.assertIsNotNone(new_rsa.private_key)
        self.assertIsNotNone(new_rsa.public_key)

    def test_large_file_encryption_decryption(self):
        self.rsa.generate_keys()

        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "input.txt")
            enc_path = os.path.join(temp_dir, "enc.bin")
            dec_path = os.path.join(temp_dir, "dec.txt")

            original_data = os.urandom(600)
            with open(input_path, "wb") as f:
                f.write(original_data)

            self.rsa.encrypt_file(input_path, enc_path)
            self.rsa.decrypt_file(enc_path, dec_path)

            with open(dec_path, "rb") as f:
                decrypted_data = f.read()

            self.assertEqual(original_data, decrypted_data)

    def test_encryption_actually_changes_data(self):
        self.rsa.generate_keys()

        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "input.txt")
            enc_path = os.path.join(temp_dir, "enc.bin")

            original_data = b"This is a secret message that should be encrypted"
            with open(input_path, "wb") as f:
                f.write(original_data)

            self.rsa.encrypt_file(input_path, enc_path)

            with open(enc_path, "rb") as f:
                encrypted_data = f.read()

            self.assertNotEqual(original_data, encrypted_data)

if __name__ == '__main__':
    unittest.main()
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

class RSA:
    def __init__(self, key_size=2048, public_exponent=65537):
        self.key_size = key_size
        self.public_exponent = public_exponent
        self.private_key = None
        self.public_key = None

        self.hash_algo = hashes.SHA256()
        self.hash_size = self.hash_algo.digest_size

        self.max_encrypt_block_size = (self.key_size // 8) - 2 * self.hash_size - 2
        self.decrypt_block_size = self.key_size // 8

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=self.public_exponent,
            key_size=self.key_size,
        )
        self.public_key = self.private_key.public_key()

    def get_private_key_bytes(self) -> bytes:
        if not self.private_key: raise ValueError("Private key not generated")
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_public_key_bytes(self) -> bytes:
        if not self.public_key: raise ValueError("Public key not generated")
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_private_key(self, key_bytes: bytes):
        self.private_key = serialization.load_pem_private_key(key_bytes, password=None)

    def load_public_key(self, key_bytes: bytes):
        self.public_key = serialization.load_pem_public_key(key_bytes)

    def _encrypt_block(self, chunk: bytes) -> bytes:
        return self.public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_algo),
                algorithm=self.hash_algo,
                label=None
            )
        )

    def _decrypt_block(self, chunk: bytes) -> bytes:
        return self.private_key.decrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_algo),
                algorithm=self.hash_algo,
                label=None
            )
        )

    def encrypt_file(self, input_path, output_path):
        if not self.public_key: raise ValueError("Public key not loaded")
        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            while True:
                chunk = f_in.read(self.max_encrypt_block_size)
                if not chunk: break
                f_out.write(self._encrypt_block(chunk))

    def decrypt_file(self, input_path, output_path):
        if not self.private_key: raise ValueError("Private key not loaded")
        with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
            while True:
                chunk = f_in.read(self.decrypt_block_size)
                if not chunk: break
                f_out.write(self._decrypt_block(chunk))
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.exceptions import InvalidSignature

class DSA:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        self.hash_algo = hashes.SHA256()

    def generate_keys(self):
        self.private_key = dsa.generate_private_key(key_size=self.key_size)
        self.public_key = self.private_key.public_key()

    def get_private_key_bytes(self) -> bytes:
        if not self.private_key:
            raise ValueError("Private key not generated or loaded")
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def get_public_key_bytes(self) -> bytes:
        if not self.public_key:
            raise ValueError("Public key not generated or loaded")
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_private_key(self, key_bytes: bytes):
        self.private_key = serialization.load_pem_private_key(key_bytes, password=None)

    def load_public_key(self, key_bytes: bytes):
        self.public_key = serialization.load_pem_public_key(key_bytes)

    def sign_text(self, text: str) -> str:
        if not self.private_key:
            raise ValueError("Private key not loaded for signing")

        data_bytes = text.encode('utf-8')
        signature_bytes = self.private_key.sign(
            data_bytes,
            self.hash_algo
        )
        return signature_bytes.hex()

    def verify_text(self, text: str, signature_hex: str) -> bool:
        if not self.public_key:
            raise ValueError("Public key not loaded for verification")

        data_bytes = text.encode('utf-8')
        try:
            signature_bytes = bytes.fromhex(signature_hex)
            self.public_key.verify(
                signature_bytes,
                data_bytes,
                self.hash_algo
            )
            return True
        except (InvalidSignature, ValueError):
            return False

    def sign_file(self, input_path: str, output_sig_path: str):
        if not self.private_key:
            raise ValueError("Private key not loaded for signing")

        hasher = hashes.Hash(self.hash_algo)

        with open(input_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)

        digest = hasher.finalize()

        signature_bytes = self.private_key.sign(
            digest,
            utils.Prehashed(self.hash_algo)
        )

        with open(output_sig_path, "w", encoding="utf-8") as sig_file:
            sig_file.write(signature_bytes.hex())

    def verify_file(self, input_path: str, sig_path: str) -> bool:
        if not self.public_key:
            raise ValueError("Public key not loaded for verification")

        with open(sig_path, "r", encoding="utf-8") as sig_file:
            signature_hex = sig_file.read().strip()

        try:
            signature_bytes = bytes.fromhex(signature_hex)
        except ValueError:
            return False

        hasher = hashes.Hash(self.hash_algo)

        with open(input_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)

        digest = hasher.finalize()

        try:
            self.public_key.verify(
                signature_bytes,
                digest,
                utils.Prehashed(self.hash_algo)
            )
            return True
        except InvalidSignature:
            return False
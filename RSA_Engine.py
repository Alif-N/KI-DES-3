# RSA_Engine.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class RSA_Engine:
    """Class untuk operasi Kunci Asimetris (RSA)"""
    
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None

    def generate_key_pair(self):
        """Menghasilkan pasangan kunci RSA publik/privat"""
        key = RSA.generate(self.key_size)
        self.private_key = key
        self.public_key = key.public_key()
        return self.public_key.export_key('PEM').decode()

    def get_public_key_pem(self):
        """Mengembalikan kunci publik dalam format PEM string"""
        if self.public_key:
            return self.public_key.export_key('PEM').decode()
        return None

    def load_public_key(self, public_key_pem):
        """Memuat kunci publik dari string PEM"""
        return RSA.import_key(public_key_pem)

    def encrypt_with_public_key(self, data_bytes: bytes, public_key_pem: str) -> str:
        """Enkripsi data menggunakan Public Key (ditujukan untuk Server)"""
        recipient_key = self.load_public_key(public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        encrypted = cipher_rsa.encrypt(data_bytes)
        # Mengembalikan string base64 untuk pengiriman
        return base64.b64encode(encrypted).decode()

    def decrypt_with_private_key(self, encrypted_b64: str) -> bytes:
        """Dekripsi data menggunakan Private Key (milik sendiri)"""
        if not self.private_key:
            raise Exception("Kunci privat belum diinisialisasi.")
            
        encrypted_bytes = base64.b64decode(encrypted_b64)
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        decrypted = cipher_rsa.decrypt(encrypted_bytes)
        return decrypted
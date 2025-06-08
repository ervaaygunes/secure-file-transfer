from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib
import os

class SecurityManager:
    def __init__(self):
        # Anahtar oluştur veya yükle
        self.key = self._load_or_generate_key()
        self.cipher_suite = Fernet(self.key)
    
    def _load_or_generate_key(self):
        """Anahtar dosyasını yükle veya yeni anahtar oluştur"""
        key_file = "encryption.key"
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, "wb") as f:
                f.write(key)
            return key
    
    def encrypt_data(self, data):
        """Veriyi şifrele"""
        if isinstance(data, str):
            data = data.encode()
        return self.cipher_suite.encrypt(data)
    
    def decrypt_data(self, encrypted_data):
        """Şifrelenmiş veriyi çöz"""
        return self.cipher_suite.decrypt(encrypted_data)
    
    def calculate_file_hash(self, file_path):
        """Dosyanın SHA-256 hash değerini hesapla"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def verify_file_integrity(self, file_path, original_hash):
        """Dosya bütünlüğünü doğrula"""
        current_hash = self.calculate_file_hash(file_path)
        return current_hash == original_hash
    
    def generate_password_hash(self, password):
        """Şifre hash'i oluştur"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def verify_password(self, password, stored_key, salt):
        """Şifreyi doğrula"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        try:
            kdf.verify(password.encode(), base64.urlsafe_b64decode(stored_key))
            return True
        except:
            return False 
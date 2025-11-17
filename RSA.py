# RSA_Engine.py (Implementasi From Scratch)

import random
import math
import base64
from typing import Tuple

# --- FUNGSI MATEMATIKA DASAR UNTUK RSA ---

def is_prime(n, k=5):
    """Sederhana Miller-Rabin test untuk memeriksa bilangan prima (untuk demo)"""
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False
    
    # Tulis n-1 sebagai 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1
    
    # Loop k kali
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
            
    return True

def generate_large_prime(bits):
    """Menghasilkan bilangan prima N-bit acak"""
    while True:
        p = random.getrandbits(bits)
        if p.bit_length() != bits:
            p = random.getrandbits(bits) | (1 << (bits - 1)) | 1 # Pastikan panjang bit dan ganjil
        if is_prime(p):
            return p

def extended_gcd(a, b) -> Tuple[int, int, int]:
    """Algoritma Euclidean Diperluas: ax + by = gcd(a, b)"""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    """Menghitung invers modular: a^-1 mod m"""
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        # Tidak ada invers modular jika gcd(a, m) != 1
        raise Exception('Invers modular tidak ada')
    return (x % m + m) % m

# --- CLASS RSA ENGINE ---

class RSA_Engine:
    """Implementasi RSA From Scratch untuk distribusi kunci"""
    
    def __init__(self, key_bits=256): # Menggunakan key_bits kecil agar cepat untuk demo
        self.key_bits = key_bits
        self.n = None
        self.e = 65537 # Kunci publik standar (umumnya digunakan)
        self.d = None
        self.public_key_pem = None
        self.private_key_pem = None # Untuk menyimpan (n, d)
        
    def generate_key_pair(self) -> str:
        """Menghasilkan pasangan kunci (n, e, d)"""
        
        # 1. Pilih dua bilangan prima besar p dan q
        p = generate_large_prime(self.key_bits // 2)
        q = generate_large_prime(self.key_bits // 2)
        
        # Pastikan p != q
        while p == q:
             q = generate_large_prime(self.key_bits // 2)

        # 2. Hitung modulus n
        self.n = p * q
        
        # 3. Hitung Euler's totient phi(n)
        phi = (p - 1) * (q - 1)
        
        # 4. Hitung kunci privat d (invers modular e mod phi)
        self.d = mod_inverse(self.e, phi)
        
        # 5. Format kunci untuk transfer
        # Kunci Publik: (n, e)
        # Kunci Privat: (n, d)
        
        # Kita akan menggunakan format sederhana "BASE64(n),BASE64(e)" untuk transfer
        n_b64 = base64.b64encode(str(self.n).encode()).decode()
        e_b64 = base64.b64encode(str(self.e).encode()).decode()
        d_b64 = base64.b64encode(str(self.d).encode()).decode()
        
        # Menyimpan Public Key dan Private Key sebagai string untuk penggunaan internal
        self.public_key_pem = f"N:{n_b64},E:{e_b64}"
        self.private_key_pem = f"N:{n_b64},D:{d_b64}"
        
        return self.public_key_pem

    def load_public_key(self, public_key_pem: str) -> Tuple[int, int]:
        """Memuat Public Key (n, e) dari format string"""
        try:
            parts = public_key_pem.split(',')
            n_str = parts[0].split(':')[1]
            e_str = parts[1].split(':')[1]
            
            n = int(base64.b64decode(n_str).decode())
            e = int(base64.b64decode(e_str).decode())
            return n, e
        except:
            raise ValueError("Format Public Key tidak valid.")


    def encrypt_with_public_key(self, data_bytes: bytes, public_key_pem: str) -> str:
        """Enkripsi data (Secret Key DES) menggunakan Public Key penerima"""
        n, e = self.load_public_key(public_key_pem)
        
        # Konversi bytes data (kunci DES) ke integer (m)
        m = int.from_bytes(data_bytes, byteorder='big')
        
        # Cek jika m terlalu besar untuk n (penting!)
        if m >= n:
            raise ValueError("Pesan terlalu besar untuk modulus RSA. Gunakan padding/chunking.")
            
        # Enkripsi: c = m^e mod n
        c = pow(m, e, n)
        
        # Mengembalikan ciphertext sebagai string base64 dari integer
        return base64.b64encode(str(c).encode()).decode()

    def decrypt_with_private_key(self, encrypted_b64: str) -> bytes:
        """Dekripsi data menggunakan Private Key (n, d) milik sendiri"""
        
        # Load Private Key sendiri (n, d)
        if not self.private_key_pem:
             raise Exception("Private Key belum diinisialisasi.")
             
        parts = self.private_key_pem.split(',')
        n_str = parts[0].split(':')[1]
        d_str = parts[1].split(':')[1]
        
        n = int(base64.b64decode(n_str).decode())
        d = int(base64.b64decode(d_str).decode())
        
        # Konversi ciphertext base64 kembali ke integer (c)
        c = int(base64.b64decode(encrypted_b64).decode())
        
        # Dekripsi: m = c^d mod n
        m = pow(c, d, n)
        
        # Konversi integer m kembali ke bytes data (kunci DES, 8 byte)
        # Tentukan panjang kunci DES (8 byte)
        key_length = 8
        decrypted_bytes = m.to_bytes(key_length, byteorder='big')
        
        return decrypted_bytes
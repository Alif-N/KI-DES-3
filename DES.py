# des_engine.py
# Mengandung class DES lengkap yang Anda sediakan.
from typing import List
import binascii

class DES:
    """Implementasi DES (Data Encryption Standard) dengan enkripsi dan dekripsi"""
    
    # Tabel Permutasi Awal (Initial Permutation)
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]

    # Tabel Permutasi Akhir (Final Permutation)
    FP = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

    # Tabel Ekspansi (Expansion)
    E = [32, 1, 2, 3, 4, 5,
         4, 5, 6, 7, 8, 9,
         8, 9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32, 1]

    # Tabel S-Box (Potongan kode S-BOX Anda)
    S_BOX = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 0, 5],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 15, 3, 12, 0],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
        # S3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        # S4
        [[7, 13, 14, 3, 4, 15, 2, 8, 1, 10, 6, 12, 11, 9, 5, 0],
         [3, 12, 10, 9, 14, 8, 1, 13, 4, 15, 2, 7, 8, 0, 6, 13],
         [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 5, 12, 1, 2, 15, 3, 10, 14, 4, 7, 6, 9, 8]],
        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 2, 10, 1, 7, 6, 4, 10, 13, 0, 5, 8, 15, 14]],
        # S6
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 6, 11, 13, 0, 5, 3, 4, 9, 8, 15, 12, 10]],
        # S7
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        # S8
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 5, 12, 1, 2, 15, 3, 10, 14, 4, 7, 6, 9, 8],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 4, 0, 5, 15, 14, 2, 3, 12]]
    ]
    # Tabel P, PC1, PC2, SHIFT sama seperti yang Anda berikan
    P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
    PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 28, 20, 12, 4, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4, 27, 19, 11, 3]
    PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
    SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    @staticmethod
    def _permute(data: List[int], perm_table: List[int]) -> List[int]:
        """Melakukan permutasi pada data berdasarkan tabel permutasi"""
        return [data[perm_table[i] - 1] for i in range(len(perm_table))]

    @staticmethod
    def _left_rotate(data: List[int], n: int) -> List[int]:
        """Rotasi kiri sebanyak n posisi"""
        return data[n:] + data[:n]

    @staticmethod
    def _xor(data1: List[int], data2: List[int]) -> List[int]:
        """Operasi XOR pada dua list biner"""
        return [data1[i] ^ data2[i] for i in range(len(data1))]

    def _generate_subkeys(self, key: List[int]) -> List[List[int]]:
        """Generate 16 subkunci dari kunci awal 64-bit"""
        permuted_key = self._permute(key, self.PC1)
        
        C = permuted_key[:28]
        D = permuted_key[28:]
        
        subkeys = []
        
        for i in range(16):
            C = self._left_rotate(C, self.SHIFT[i])
            D = self._left_rotate(D, self.SHIFT[i])
            
            combined = C + D
            subkey = self._permute(combined, self.PC2)
            subkeys.append(subkey)
        
        return subkeys
    
    def _f_function(self, R: List[int], subkey: List[int]) -> List[int]:
        """Fungsi F dalam round DES"""
        expanded = self._permute(R, self.E)
        xored = self._xor(expanded, subkey)
        
        substituted = []
        for i in range(8):
            bits = xored[i*6:(i+1)*6]
            row = (bits[0] << 1) | bits[5]
            col = (bits[1] << 3) | (bits[2] << 2) | (bits[3] << 1) | bits[4]
            value = self.S_BOX[i][row][col]
            substituted.extend([(value >> (3-j)) & 1 for j in range(4)])
        
        result = self._permute(substituted, self.P)
        return result
    
    @staticmethod
    def _pad(data: bytes) -> bytes:
        """Menambahkan padding PKCS#7 ke data (untuk blok 8 byte)"""
        block_size = 8
        padding_needed = block_size - (len(data) % block_size)
        # Nilai padding adalah jumlah byte yang ditambahkan
        padding_value = padding_needed
        return data + bytes([padding_value] * padding_needed)

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """Menghapus padding PKCS#7 dari data"""
        if not data:
            raise ValueError("Data kosong, tidak dapat menghapus padding.")
        
        # Nilai padding berada di byte terakhir
        padding_value = data[-1]
        
        # Cek validitas (optional tapi disarankan)
        if padding_value == 0 or padding_value > 8:
            # Ini mungkin bukan padding PKCS#5/7 atau datanya korup
            raise ValueError(f"Nilai padding tidak valid: {padding_value}")
        
        # Cek apakah semua byte padding memiliki nilai yang benar
        if data[-padding_value:] != bytes([padding_value] * padding_value):
            # Jika byte terakhir adalah '\x04', pastikan 4 byte terakhir adalah '\x04'
            raise ValueError("Data padding korup atau tidak valid.")
        
        return data[:-padding_value]

    def encrypt(self, plaintext: str, key: str) -> str:
        """Enkripsi plaintext menggunakan DES dengan chaining Mode ECB."""
        if len(key) != 8:
             raise ValueError("Kunci harus tepat 8 karakter (64 bit).")
        
        key_bits = [int(bit) for byte in key.encode() for bit in format(byte, '08b')]
        subkeys = self._generate_subkeys(key_bits)
        
        # 1. Padding
        padded_bytes = self._pad(plaintext.encode('utf-8'))
        
        ciphertext_hex = ""
        # 2. Iterasi setiap blok 8 byte (64 bit)
        for i in range(0, len(padded_bytes), 8):
            block_bytes = padded_bytes[i:i+8]
            block_bits = [int(bit) for byte in block_bytes for bit in format(byte, '08b')]
            
            # Algoritma DES standar (sama seperti sebelumnya)
            permuted = self._permute(block_bits, self.IP)
            L, R = permuted[:32], permuted[32:]
            
            for i in range(16):
                L, R = R, self._xor(L, self._f_function(R, subkeys[i]))
            
            combined = R + L
            block_ciphertext_bits = self._permute(combined, self.FP)
            
            block_ciphertext_bytes = bytes([int(''.join(map(str, block_ciphertext_bits[j:j+8])), 2) 
                                       for j in range(0, 64, 8)])
            
            # Kumpulkan hasil heksadesimal
            ciphertext_hex += binascii.hexlify(block_ciphertext_bytes).decode() 
            
        return ciphertext_hex 

    def decrypt(self, ciphertext: str, key: str) -> str:
        """Dekripsi ciphertext menggunakan DES (ECB Mode) dan menghapus padding."""
        if len(ciphertext) % 16 != 0 or len(key) != 8:
             raise ValueError("Ciphertext harus kelipatan 16 karakter heksadesimal dan Kunci harus 8 karakter.")
             
        key_bits = [int(bit) for byte in key.encode() for bit in format(byte, '08b')]
        subkeys = self._generate_subkeys(key_bits)
        
        ciphertext_bytes = binascii.unhexlify(ciphertext)
        
        decrypted_bytes = b''
        
        # 1. Iterasi setiap blok 8 byte (16 karakter heks)
        for i in range(0, len(ciphertext_bytes), 8):
            block_ciphertext_bytes = ciphertext_bytes[i:i+8]
            block_ciphertext_bits = [int(bit) for byte in block_ciphertext_bytes for bit in format(byte, '08b')]
            
            # Algoritma DES standar (sama seperti sebelumnya)
            permuted = self._permute(block_ciphertext_bits, self.IP)
            L = permuted[:32]
            R = permuted[32:]
            
            for i in range(15, -1, -1):
                L, R = R, self._xor(L, self._f_function(R, subkeys[i]))
            
            combined = R + L
            block_plaintext_bits = self._permute(combined, self.FP)
            
            block_plaintext_bytes = bytes([int(''.join(map(str, block_plaintext_bits[j:j+8])), 2) 
                                   for j in range(0, 64, 8)])
            
            decrypted_bytes += block_plaintext_bytes

        # 2. Hapus Padding
        unpadded_bytes = self._unpad(decrypted_bytes)
        
        # Mengembalikan string plaintext
        plaintext = unpadded_bytes.decode('utf-8')
        return plaintext
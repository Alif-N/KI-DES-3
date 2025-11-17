import socket
import sys
from DES import DES
from RSA_Engine import RSA_Engine 
import base64

# Konfigurasi Jaringan Client
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8000

# Inisialisasi RSA Engine di Client
client_rsa = RSA_Engine()
# Client membuat pasangan kuncinya sendiri saat start
CLIENT_PUBLIC_KEY_PEM = client_rsa.generate_key_pair() 

# Kunci DES Awal
SHARED_KEY = None 
ENCRYPTED_DES_KEY_B64 = None

# Memulai client TCP.
def start_client():
    global SHARED_KEY, ENCRYPTED_DES_KEY_B64
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"[CLIENT] Mencoba terhubung ke {SERVER_HOST}:{SERVER_PORT}...")
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print("[CLIENT] Berhasil terhubung.")
        print(f"[CLIENT] Kunci Bersama: {SHARED_KEY}")

        # Terima pesan awal dari server (status koneksi)
        initial_text = client_socket.recv(1024).decode('utf-8').strip()

        # 1. Kirim Kunci Publik Client ke Server
        client_socket.send(f"CLIENT_PUBLIC_KEY:{CLIENT_PUBLIC_KEY_PEM}".encode('utf-8'))
        print("[CLIENT RSA] Mengirim Public Key ke Server...")
        
        # 2. Terima balasan dari Server (Kunci DES Terenkripsi atau status koneksi)
        # Kita menggunakan loop untuk menerima semua data dari Server
        received_data = ""
        
        if initial_text:
            print(f"\n[SERVER STATUS]: {initial_text}")
            print("-" * 40)

        while True:
            # Meningkatkan buffer recv untuk pertukaran kunci
            chunk = client_socket.recv(4096).decode('utf-8').strip()
            if not chunk:
                break
            received_data += chunk
            
            # Cari Kunci DES Terenkripsi
            if "ENCRYPTED_DES_KEY:" in received_data:
                parts = received_data.split("ENCRYPTED_DES_KEY:")
                ENCRYPTED_DES_KEY_B64 = parts[1].split('-----')[0].strip() # Ambil bagian kuncinya
                print("[CLIENT RSA] Menerima Kunci DES Terenkripsi.")
                break
            
            # Jika Server mengirim pesan lain (misal status koneksi)
            elif "Berhasil terhubung" in received_data:
                 print(f"\n[SERVER STATUS]: {received_data}")
                 print("-" * 40)
                 received_data = ""
                 continue
            
            # Jika tidak ada kunci yang ditemukan
            if len(received_data) > 4096: # Batasi ukuran data yang dicari
                break

        # 3. Dekripsi Kunci Sesi DES menggunakan Private Key Client
        if ENCRYPTED_DES_KEY_B64:
            try:
                print("[CLIENT RSA] Mendekripsi Kunci Sesi DES menggunakan Private Key sendiri...")
                
                # Dekripsi menggunakan Private Key yang hanya dimiliki Client ini
                decrypted_bytes = client_rsa.decrypt_with_private_key(ENCRYPTED_DES_KEY_B64)
                SHARED_KEY = decrypted_bytes.decode('utf-8')
                
                if len(SHARED_KEY) != 8:
                    raise ValueError("Kunci sesi DES yang didekripsi tidak valid (bukan 8 karakter).")
                    
                print(f"[CLIENT KRIPTO] Kunci Sesi DES Berhasil Didekripsi. Kunci Aktif: ********")
                print("-" * 40)
                
            except Exception as e:
                print(f"[ERROR KRIPTO] Gagal mendekripsi kunci sesi: {e}")
                SHARED_KEY = "keamanan" # Fail-safe
        else:
            print("[CLIENT KRIPTO] Kunci Sesi DES tidak diterima. Menggunakan kunci default.")
            SHARED_KEY = "keamanan" 
            
        # 4. Lanjutkan Komunikasi DES
        print(f"[CLIENT] Siap berkomunikasi menggunakan Kunci Sesi yang diperoleh.")
        des_engine = DES()

        while True:
            # 1. Client mengirim data (ter-enkripsi)
            # Hapus validasi 8 karakter
            message = input("Client Kirim (Plaintext, 'KELUAR' untuk keluar): ")
            
            if message.lower() == 'keluar':
                client_socket.send("keluar".encode('utf-8')) # Kirim sinyal keluar non-enkripsi
                break
            
            # 2. Enkripsi dan Kirim data
            try:
                # Sekarang DES.encrypt dapat menerima string panjang apa pun
                ciphertext_hex = des_engine.encrypt(message, SHARED_KEY)
                print("-" * 40)
                print(f"[CLIENT ENKRIPSI]: Mengirim {ciphertext_hex} (Panjang Hex: {len(ciphertext_hex)})...")
                client_socket.send(ciphertext_hex.encode('utf-8'))
            except ValueError as e:
                print(f"[ERROR KRIPTO] {e}. Coba lagi.")
                continue 

            # 3. Terima data balasan terenkripsi
            print("\n[CLIENT] Menunggu Balasan...")
            ciphertext_response_hex = client_socket.recv(4096).decode('utf-8').strip() # Tingkatkan buffer
            
            if not ciphertext_response_hex or ciphertext_response_hex.lower() == 'keluar':
                print("[INFO] Client Lawan atau Server memutuskan koneksi.")
                break
            
            # Hapus validasi panjang 16 karakter, sekarang bisa lebih panjang
            if len(ciphertext_response_hex) % 16 != 0:
                print(f"[WARN] Data heks diterima bukan kelipatan 16: {len(ciphertext_response_hex)}. Diabaikan.")
                continue

            # 4. Dekripsi data balasan
            plaintext_response = des_engine.decrypt(ciphertext_response_hex, SHARED_KEY)
            print("-" * 40)
            print(f"Ciphertext Diterima: {ciphertext_response_hex}")
            print(f"[CLIENT DEKRIPSI]: '{plaintext_response}'")
            print("-" * 40)
            
    except ConnectionRefusedError:
        print(f"[ERROR] Koneksi ditolak. Pastikan Server berjalan di {SERVER_HOST}:{SERVER_PORT}")
    except ValueError as e:
        print(f"[ERROR KRIPTO] Masalah dengan data/kunci DES: {e}")
    except Exception as e:
        print(f"[ERROR] Terjadi kesalahan: {e}")
    finally:
        client_socket.close()
        print("[CLIENT] Koneksi ditutup.")
        
if __name__ == "__main__":
    start_client()
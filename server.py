import socket
import threading
import sys
import time
import os
import random
import string
from DES import DES 
from RSA_Engine import RSA_Engine

# Konfigurasi Jaringan Server
HOST = '127.0.0.1'
PORT = 8000

# Inisialisasi RSA Engine di Server
server_rsa = RSA_Engine()
SERVER_PUBLIC_KEY = server_rsa.generate_key_pair() # Server membuat pasangan kunci RSA

# Kunci DES yang akan digunakan bersama (Dibuat secara acak)
SESSION_DES_KEY = None

# Server tidak lagi menggunakan DES engine atau Kunci Bersama.
# Server HANYA akan me-relay data yang diterimanya.

# Variabel global untuk menyimpan soket DAN KUNCI PUBLIK kedua client
client_a_socket = None
client_b_socket = None
client_a_pubkey = None # Kunci Publik Client A
client_b_pubkey = None # Kunci Publik Client B
lock = threading.Lock()

# Fungsi untuk menghasilkan kunci DES acak 8 karakter
def generate_des_key():
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(8))

# Fungsi untuk menerima kunci publik dari Client
def receive_client_pubkey(conn, client_label):
    global client_a_pubkey, client_b_pubkey
    
    # Terima Public Key Client (Buffer disesuaikan untuk RSA Key)
    data = conn.recv(4096).decode('utf-8').strip()
    
    if data.startswith("CLIENT_PUBLIC_KEY:"):
        pubkey_pem = data[len("CLIENT_PUBLIC_KEY:"):].strip()
        
        with lock:
            if client_label == 'Client A':
                client_a_pubkey = pubkey_pem
            else:
                client_b_pubkey = pubkey_pem
        
        print(f"[SERVER KEY] {client_label} Public Key diterima.")
        return True
    return False

# Fungsi baru untuk mengirim Kunci DES terenkripsi ke Client
def send_encrypted_key(client_conn, client_pubkey_pem):
    global SESSION_DES_KEY
    if not SESSION_DES_KEY:
        SESSION_DES_KEY = generate_des_key()
        print(f"[SERVER] Kunci Sesi DES Dibuat: {SESSION_DES_KEY}")

    try:
        # **LANGKAH KRITIS:** Enkripsi Kunci DES menggunakan Public Key MILIK CLIENT
        encrypted_key = server_rsa.encrypt_with_public_key(
            SESSION_DES_KEY.encode('utf-8'), 
            client_pubkey_pem # Menggunakan Public Key Client
        )
        
        # Kirim Kunci DES yang sudah terenkripsi RSA
        client_conn.send(f"ENCRYPTED_DES_KEY:{encrypted_key}".encode('utf-8'))
        print(f"[SERVER KEY] Kunci DES terenkripsi dikirim ke Client.")
        return True
    except Exception as e:
        print(f"[SERVER ERROR] Gagal mengenkripsi/mengirim kunci: {e}")
        return False

# Fungsi untuk mengirim pesan dari satu client ke client lain
def relay_message(sender_conn, receiver_conn, sender_label, receiver_label):
    while True:
        try:
            # Terima data dari pengirim (Ciphertext dari Client)
            ciphertext_hex = sender_conn.recv(1024).decode('utf-8').strip()

            if not ciphertext_hex or ciphertext_hex.lower() == 'keluar':
                print(f"[SERVER] {sender_label} meminta keluar. Memberi sinyal keluar ke {receiver_label}.")
                if receiver_conn:
                    # Kirim sinyal keluar (non-enkripsi) ke client lain
                    receiver_conn.send("keluar".encode('utf-8')) 
                break
                
            # Server hanya mencetak log dan me-relay
            print("-" * 40)
            print(f"[RELAY] Dari {sender_label} ke {receiver_label}: {ciphertext_hex}")
            print("-" * 40)
            
            # Kirim data ke penerima
            if receiver_conn:
                receiver_conn.send(ciphertext_hex.encode('utf-8'))
            else:
                print(f"[SERVER WARN] {receiver_label} belum terhubung. Pesan diabaikan.")

        except Exception as e:
            print(f"[SERVER ERROR] Koneksi {sender_label} terputus: {e}")
            if receiver_conn:
                 # Kirim sinyal keluar ke client lain jika terjadi kesalahan
                try:
                    receiver_conn.send("keluar".encode('utf-8'))
                except:
                    pass
            break
            
    # Tutup koneksi setelah loop berakhir
    try:
        sender_conn.close()
    except:
        pass

def start_server():
    global client_a_socket, client_b_socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server_socket.bind((HOST, PORT))
    except OSError as e:
        print(f"[ERROR] Tidak dapat mengikat ke {HOST}:{PORT}: {e}")
        print("Mungkin port sudah digunakan. Silakan coba lagi nanti.")
        sys.exit(1)
        
    server_socket.listen(2) # Hanya mendengarkan 2 koneksi (Client A dan Client B)
    print(f"[SERVER] Server berjalan di {HOST}:{PORT}")
    print("[SERVER] Menunggu 2 Client (A dan B) untuk terhubung...")
    
    clients = []
    
    while len(clients) < 2:
        try:
            conn, addr = server_socket.accept()
            clients.append((conn, addr))
            
            with lock:
                if len(clients) == 1:
                    client_a_socket = conn
                    client_label = 'Client A'
                else:
                    client_b_socket = conn
                    client_label = 'Client B'

            print(f"[KONEKSI] {client_label} terhubung dari {addr}")
            
            # Kirim pesan status, lalu segera terima Public Key
            conn.send(f"Berhasil terhubung sebagai {client_label}. Menunggu Public Key...".encode('utf-8'))
            receive_client_pubkey(conn, client_label)

        except KeyboardInterrupt:
            print("\n[SERVER] Server dimatikan.")
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            print(f"[SERVER ERROR] {e}")

# Setelah 2 client terhubung dan Public Keys diterima
    print("[SERVER INFO] Kedua Client terhubung. Memulai Key Exchange Terakhir...")
    
    # Validasi apakah kedua kunci sudah diterima sebelum mengirim kunci sesi
    if client_a_pubkey and client_b_pubkey:
        print("[SERVER KEY] Semua Public Key diterima. Mengirim Kunci Sesi DES...")
        
        # Kirim Kunci Sesi DES terenkripsi ke Client A
        send_encrypted_key(client_a_socket, client_a_pubkey)
        
        # Kirim Kunci Sesi DES terenkripsi ke Client B
        send_encrypted_key(client_b_socket, client_b_pubkey)
    else:
        print("[SERVER WARN] Public Key Client tidak lengkap. Tidak dapat melakukan Key Exchange Aman.")
    
    # Memulai thread relay 2 arah (A -> B) dan (B -> A)
    # Relay A -> B
    threading.Thread(target=relay_message, 
                     args=(client_a_socket, client_b_socket, 'Client A', 'Client B'), 
                     daemon=True).start()
    # Relay B -> A
    threading.Thread(target=relay_message, 
                     args=(client_b_socket, client_a_socket, 'Client B', 'Client A'), 
                     daemon=True).start()
    
    print("[SERVER] Relay aktif. Server berjalan di latar belakang.")
    print("[SERVER] Tekan Ctrl+C untuk mematikan Server.")
    
    try:
        # Jaga thread utama agar tetap hidup
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SERVER] Server dimatikan.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
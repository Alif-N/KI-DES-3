import socket
import threading
import sys
import time
import os
import random
import string
from DES import DES 
from RSA import RSA_Engine

# Konfigurasi Jaringan Server
HOST = '127.0.0.1'
PORT = 8000

# Inisialisasi RSA Engine di Server
server_rsa = RSA_Engine()
SERVER_PUBLIC_KEY = server_rsa.generate_key_pair() 

# Kunci DES yang akan digunakan bersama (Dibuat secara acak)
SESSION_DES_KEY = None

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
    
    data = ""
    # Data dari recv pertama (status awal) kemungkinan sudah diterima di start_server.
    # Kita hanya perlu menerima data selanjutnya yang berisi kunci publik.
    # Perbaiki: Cukup terima 1 kali yang berisi kunci publik, anggap client mengirim segera.
    try:
        conn.settimeout(3.0) # Beri batas waktu untuk menunggu kunci publik
        chunk = conn.recv(4096).decode('utf-8')
        data += chunk
        conn.settimeout(None) # Hapus batas waktu
        
        if "CLIENT_PUBLIC_KEY:" in data:
            pubkey_pem = data[data.find("CLIENT_PUBLIC_KEY:") + len("CLIENT_PUBLIC_KEY:"):].strip()
            
            with lock:
                if client_label == 'Client A':
                    client_a_pubkey = pubkey_pem
                else:
                    client_b_pubkey = pubkey_pem
            
            print(f"[SERVER KEY] {client_label} Public Key diterima.")
            return True
        else:
            print(f"[SERVER WARN] Data kunci publik tidak valid dari {client_label}.")
            return False
            
    except socket.timeout:
        print(f"[SERVER WARN] Timeout menunggu Public Key dari {client_label}.")
        return False
    except Exception as e:
        print(f"[SERVER ERROR] Gagal menerima Public Key: {e}")
        return False

# Fungsi baru untuk mengirim Kunci DES terenkripsi ke Client
def send_encrypted_key(client_conn, client_pubkey_pem):
    global SESSION_DES_KEY
    if not SESSION_DES_KEY:
        SESSION_DES_KEY = generate_des_key()
        print(f"[SERVER] Kunci Sesi DES Dibuat: {SESSION_DES_KEY}")

    try:
        encrypted_key = server_rsa.encrypt_with_public_key(
            SESSION_DES_KEY.encode('utf-8'), 
            client_pubkey_pem 
        )
        
        client_conn.send(f"ENCRYPTED_DES_KEY:{encrypted_key}".encode('utf-8'))
        print(f"[SERVER KEY] Kunci DES terenkripsi dikirim ke Client.")
        return True
    except Exception as e:
        print(f"[SERVER ERROR] Gagal mengenkripsi/mengirim kunci: {e}")
        return False

# Fungsi untuk mengirim pesan dari satu client ke client lain
def relay_message(sender_conn, receiver_conn_ref, sender_label, receiver_label):
    while True:
        try:
            # Ambil socket lawan secara thread-safe
            with lock:
                receiver_conn = receiver_conn_ref()

            # Terima data dari pengirim (Ciphertext dari Client)
            ciphertext_hex = sender_conn.recv(4096).decode('utf-8').strip()

            if not ciphertext_hex or ciphertext_hex.lower() == 'keluar':
                print(f"[SERVER] {sender_label} meminta keluar. Memberi sinyal keluar ke {receiver_label}.")
                if receiver_conn:
                    receiver_conn.send("keluar".encode('utf-8')) 
                break
                
            print("-" * 40)
            print(f"[RELAY] Dari {sender_label} ke {receiver_label}: {ciphertext_hex}")
            print("-" * 40)
            
            # Kirim data ke penerima
            if receiver_conn:
                receiver_conn.send(ciphertext_hex.encode('utf-8'))
            else:
                # Klien A dapat mengirim, tetapi klien B belum terhubung
                print(f"[SERVER WARN] {receiver_label} belum terhubung. Pesan diabaikan.") 

        except Exception as e:
            print(f"[SERVER ERROR] Koneksi {sender_label} terputus: {e}")
            with lock:
                receiver_conn = receiver_conn_ref()
            if receiver_conn:
                try:
                    receiver_conn.send("keluar".encode('utf-8'))
                except:
                    pass
            break
            
    try:
        sender_conn.close()
    except:
        pass

# Fungsi referensi untuk mengambil socket klien yang terhubung (untuk diakses oleh thread relay)
def get_client_a_socket():
    return client_a_socket

def get_client_b_socket():
    return client_b_socket

def start_server():
    global client_a_socket, client_b_socket, client_a_pubkey, client_b_pubkey
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server_socket.bind((HOST, PORT))
    except OSError as e:
        print(f"[ERROR] Tidak dapat mengikat ke {HOST}:{PORT}: {e}")
        sys.exit(1)
        
    server_socket.listen(2) 
    print(f"[SERVER] Server berjalan di {HOST}:{PORT}")
    print("[SERVER] Menunggu 2 Client (A dan B) untuk terhubung...")
    
    clients_count = 0
    
    while clients_count < 2:
        try:
            conn, addr = server_socket.accept()
            clients_count += 1
            
            with lock:
                if clients_count == 1:
                    client_a_socket = conn
                    client_label = 'Client A'
                    client_pubkey_ref = lambda: client_a_pubkey
                else:
                    client_b_socket = conn
                    client_label = 'Client B'
                    client_pubkey_ref = lambda: client_b_pubkey

            print(f"[KONEKSI] {client_label} terhubung dari {addr}")
            
            # Kirim pesan status awal
            conn.send(f"Berhasil terhubung sebagai {client_label}. Menunggu Public Key...".encode('utf-8'))
            
            # Terima Public Key
            pubkey_received = receive_client_pubkey(conn, client_label)

            # Jika ini klien kedua yang terhubung, segera lakukan key exchange
            if clients_count == 2 and pubkey_received:
                print("[SERVER INFO] Kedua Client terhubung. Memulai Key Exchange Terakhir...")
                
                # Cek dan kirim kunci sesi ke A dan B
                if client_a_pubkey and client_b_pubkey:
                    # Kirim Kunci Sesi DES terenkripsi ke Client A
                    send_encrypted_key(client_a_socket, client_a_pubkey)
                    
                    # Kirim Kunci Sesi DES terenkripsi ke Client B
                    send_encrypted_key(client_b_socket, client_b_pubkey)
                    
                    print("[SERVER] Relay aktif. Server berjalan di latar belakang.")

                    # Memulai thread relay 2 arah (A -> B) dan (B -> A)
                    threading.Thread(target=relay_message, 
                                     args=(client_a_socket, get_client_b_socket, 'Client A', 'Client B'), 
                                     daemon=True).start()
                    
                    threading.Thread(target=relay_message, 
                                     args=(client_b_socket, get_client_a_socket, 'Client B', 'Client A'), 
                                     daemon=True).start()
                    
                    # Keluar dari loop penerimaan, lanjutkan ke loop tidur
                    break
                else:
                    print("[SERVER WARN] Public Key Client tidak lengkap. Tidak dapat melakukan Key Exchange Aman. Server ditutup.")
                    # Tutup koneksi jika gagal
                    client_a_socket.close()
                    client_b_socket.close()
                    return 
            
        except KeyboardInterrupt:
            print("\n[SERVER] Server dimatikan.")
            server_socket.close()
            sys.exit(0)
        except Exception as e:
            print(f"[SERVER ERROR] {e}")

    # Jaga thread utama agar tetap hidup
    if clients_count == 2:
        print("[SERVER] Tekan Ctrl+C untuk mematikan Server.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[SERVER] Server dimatikan.")
        finally:
            server_socket.close()
            print("[SERVER] Program selesai.")


if __name__ == "__main__":
    start_server()
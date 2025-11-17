import socket
import sys
import threading
from RSA import RSA_Engine 
from DES import DES 
import base64
import os

# Konfigurasi Jaringan Client
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8000

# Inisialisasi RSA Engine di Client (Gunakan bit kecil untuk performa)
client_rsa = RSA_Engine(key_bits=256) 
CLIENT_PUBLIC_KEY_PEM = client_rsa.generate_key_pair() 

SHARED_KEY = None 
des_engine = DES() 

# --- FUNGSI UTAMA PENERIMAAN PESAN (RECEIVING THREAD) ---
def receive_messages(client_socket, shared_key_des):
    # Set timeout agar thread dapat keluar jika terjadi masalah
    client_socket.settimeout(0.5) 
    print("\n[INFO] Thread Penerima aktif. Mendengarkan pesan dari Client lawan...")
    while True:
        try:
            # Terima data (Ciphertext)
            ciphertext_response_hex = client_socket.recv(4096).decode('utf-8').strip() 
            
            if not ciphertext_response_hex or ciphertext_response_hex.lower() == 'keluar':
                print("\n[INFO] Client Lawan atau Server memutuskan koneksi. Keluar...")
                break
            
            if len(ciphertext_response_hex) % 16 != 0:
                print(f"\n[WARN] Data heks diterima tidak valid: {len(ciphertext_response_hex)}. Diabaikan.")
                continue

            # Dekripsi data balasan
            plaintext_response = des_engine.decrypt(ciphertext_response_hex, shared_key_des)
            
            # Tampilkan pesan ke pengguna
            print("\n" + "=" * 40)
            print(f"[PESAN DITERIMA]: '{plaintext_response}'")
            print("=" * 40)
            
        except socket.timeout:
            # Lewati jika hanya timeout (agar loop terus berjalan)
            continue
        except Exception as e:
            # Jika ada error koneksi atau dekripsi
            print(f"\n[ERROR RECEIVE] Koneksi terputus atau dekripsi gagal: {e}")
            break
    
    # Keluar dari thread setelah loop selesai
    os._exit(0) # Menghentikan program utama (karena main thread mungkin menunggu input)


# --- FUNGSI UTAMA PENGIRIMAN PESAN (MAIN/SENDING THREAD) ---
def send_messages(client_socket, shared_key_des):
    print("\n[INFO] Thread Pengirim aktif. Siap mengirim pesan.")
    while True:
        try:
            message = input("Anda Kirim (Plaintext, 'KELUAR' untuk keluar): ")
            
            if message.lower() == 'keluar':
                client_socket.send("keluar".encode('utf-8'))
                break
            
            # Enkripsi dan Kirim data
            ciphertext_hex = des_engine.encrypt(message, shared_key_des)
            print(f"[CLIENT ENKRIPSI]: Mengirim {ciphertext_hex}...")
            client_socket.send(ciphertext_hex.encode('utf-8'))
            
        except Exception as e:
            print(f"\n[ERROR SEND] Koneksi terputus atau enkripsi gagal: {e}")
            break
    
    # Keluar dari thread setelah loop selesai
    os._exit(0) # Menghentikan program


def start_client():
    global SHARED_KEY
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        print(f"[CLIENT] Mencoba terhubung ke {SERVER_HOST}:{SERVER_PORT}...")
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        print("[CLIENT] Berhasil terhubung.")
        
        # Non-aktifkan timeout setelah connect
        client_socket.settimeout(None)

        # --- FASE 1: KEY EXCHANGE (Sinkron) ---
        
        # 1a. TUNGGU DAN TERIMA PESAN STATUS KONEKSI AWAL DARI SERVER
        initial_status = client_socket.recv(4096).decode('utf-8').strip()
        
        if initial_status:
            print(f"\n[SERVER STATUS]: {initial_status}")
            print("-" * 40)

        # 1b. KIRIM KUNCI PUBLIK CLIENT KE SERVER
        client_socket.send(f"CLIENT_PUBLIC_KEY:{CLIENT_PUBLIC_KEY_PEM}".encode('utf-8'))
        print("[CLIENT RSA] Mengirim Public Key ke Server...")
        
        # 2. Terima Kunci DES Terenkripsi dari Server
        received_data = ""
        while True:
            # Terima data chunk hingga kunci DES ditemukan
            # Gunakan timeout agar tidak blocking selamanya jika server gagal mengirim kunci
            client_socket.settimeout(5.0) 
            try:
                chunk = client_socket.recv(8192).decode('utf-8') 
            except socket.timeout:
                print("[ERROR KRIPTO] Timeout menunggu kunci terenkripsi dari Server.")
                break
            
            if not chunk: break
            received_data += chunk
            
            if "ENCRYPTED_DES_KEY:" in received_data:
                parts = received_data.split("ENCRYPTED_DES_KEY:")
                # Ambil bagian kunci yang di-base64-kan
                encrypted_key_b64 = parts[1].strip() 
                
                print("[CLIENT RSA] Menerima Kunci DES Terenkripsi.")
                
                # 3. Dekripsi Kunci Sesi DES
                try:
                    decrypted_bytes = client_rsa.decrypt_with_private_key(encrypted_key_b64)
                    # Hapus potensi padding byte nol (byte order big)
                    SHARED_KEY = decrypted_bytes.decode('utf-8', errors='ignore').strip('\x00')
                    
                    if len(SHARED_KEY) != 8:
                        raise ValueError(f"Kunci sesi DES yang didekripsi tidak valid ({len(SHARED_KEY)} karakter).")
                         
                    print(f"[CLIENT KRIPTO] Kunci Sesi DES Berhasil Didekripsi. Kunci Aktif: ********")
                    print("-" * 40)
                    client_socket.settimeout(None) # Hapus timeout setelah berhasil
                    break 
                except Exception as e:
                     print(f"[ERROR KRIPTO] Gagal mendekripsi atau memvalidasi kunci: {e}")
                     SHARED_KEY = None 
            
            # Terima pesan status lain jika ada
            elif "Berhasil terhubung" in received_data:
                 print(f"\n[SERVER STATUS]: {received_data}")
                 received_data = ""
                 
            if len(received_data) > 8192: 
                print("[WARN] Buffer terlalu besar, keluar dari loop penerimaan kunci.")
                break

        if not SHARED_KEY:
            raise Exception("Gagal mendapatkan Kunci Sesi DES dari Server.")

        # --- FASE 2: MEMULAI KOMUNIKASI ASINKRON (Multithreading) ---
        
        # Thread untuk menerima pesan 
        receive_thread = threading.Thread(target=receive_messages, 
                                          args=(client_socket, SHARED_KEY), 
                                          daemon=True)
        receive_thread.start()

        # Thread utama menangani pengiriman pesan
        send_messages(client_socket, SHARED_KEY)
        
    except ConnectionRefusedError:
        print(f"\n[ERROR] Koneksi ditolak. Pastikan Server berjalan.")
    except Exception as e:
        print(f"\n[ERROR] Terjadi kesalahan: {e}")
    finally:
        if 'client_socket' in locals():
            try:
                client_socket.close()
            except:
                pass
        print("\n[CLIENT] Koneksi ditutup. Program selesai.")
        # os._exit(0) # Tidak diperlukan jika send_messages yang mengakhirinya
        sys.exit(0)

if __name__ == "__main__":
    start_client()
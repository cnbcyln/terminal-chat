import socket
import threading
import sys
import os
import tty
import termios
import random
import string
import base64
import subprocess

# --- Otomatik Modül Yükleme Sistemi ---
def install_package(package_name):
    """Eksik paketi otomatik olarak yükler."""
    print(f"📦 {package_name} paketi yüklü değil. Otomatik yükleniyor...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
        print(f"✅ {package_name} başarıyla yüklendi!")
        return True
    except subprocess.CalledProcessError:
        print(f"❌ {package_name} yüklenirken hata oluştu. Manuel olarak yüklemeyi deneyin:")
        print(f"   pip install {package_name}")
        return False

def import_with_auto_install():
    """Gerekli modülleri yükleyip import eder."""
    global Fernet, hashes, PBKDF2HMAC
    
    # cryptography modülünü dene
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        print("🔒 Şifreleme modülleri başarıyla yüklendi.")
    except ImportError as e:
        print("⚠️  Şifreleme modülleri bulunamadı.")
        if install_package("cryptography"):
            try:
                from cryptography.fernet import Fernet
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                print("🔒 Şifreleme modülleri başarıyla yüklendi.")
            except ImportError:
                print("❌ Şifreleme modülleri yüklenemedi. Program şifreleme olmadan çalışacak.")
                return False
        else:
            print("❌ Otomatik yükleme başarısız. Program şifreleme olmadan çalışacak.")
            return False
    return True

# Modülleri yükle
ENCRYPTION_AVAILABLE = import_with_auto_install()

# --- Ortak Ayarlar ---
DEFAULT_PORT = 12345
SERVER_PORT = None  # Sunucu tarafından belirlenen dinamik port

def find_available_port(start_port=DEFAULT_PORT):
    """Başlangıç portundan itibaren müsait bir port bulur."""
    import socket
    port = start_port
    max_attempts = 50  # Maksimum 50 port deneyeceğiz
    
    for attempt in range(max_attempts):
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_socket.bind(('0.0.0.0', port))
            test_socket.close()
            print(f"✅ Port {port} müsait!")
            return port
        except OSError:
            print(f"⚠️  Port {port} kullanımda, {port + 1} deneniyor...")
            port += 1
    
    # Hiçbir port bulunamadıysa varsayılan aralığı dene
    print("🔍 Alternatif port aralığı deneniyor...")
    for port in range(8000, 9000):
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_socket.bind(('0.0.0.0', port))
            test_socket.close()
            print(f"✅ Alternatif port {port} bulundu!")
            return port
        except OSError:
            continue
    
    raise Exception("❌ Müsait port bulunamadı! Lütfen sistem yöneticinize başvurun.")

def get_local_ip():
    """Makinenin yerel IP adresini otomatik olarak bulur."""
    try:
        # Google DNS'e bağlanarak yerel IP'yi öğren (gerçek connection açmaz)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        # Fallback: hostname üzerinden IP al
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            # Son çare: localhost
            return "127.0.0.1"

# ==============================================================================
# SUNUCU TARAFI MANTIĞI (server.py'dan taşındı)
# ==============================================================================

rooms = {}

def generate_room_id():
    """4 haneli rastgele oda ID'si oluşturur."""
    return ''.join(random.choices(string.digits, k=4))

def check_username_availability(room_id, username):
    """Bir odada kullanıcı adının müsait olup olmadığını kontrol eder."""
    if room_id not in rooms:
        return True
    
    existing_usernames = [name.lower() for name in rooms[room_id]["usernames"].values()]
    return username.lower() not in existing_usernames

def suggest_alternative_username(room_id, base_username):
    """Mevcut olmayan bir kullanıcı adı önerir."""
    counter = 2
    while True:
        suggested_name = f"{base_username}{counter}"
        if check_username_availability(room_id, suggested_name):
            return suggested_name
        counter += 1
        if counter > 99:  # Sınır koy
            break
    
    # Son çare olarak rastgele sayı ekle
    import time
    random_suffix = str(int(time.time()) % 1000)
    return f"{base_username}_{random_suffix}"

# --- Şifreleme Fonksiyonları ---
def generate_key_from_room_id(room_id):
    """Oda ID'sine göre şifreleme anahtarı oluşturur."""
    if not ENCRYPTION_AVAILABLE:
        return None
    
    # Oda ID'sini 16 byte salt haline getir
    salt = room_id.encode('utf-8').ljust(16, b'0')[:16]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = base64.urlsafe_b64encode(kdf.derive(b"terminal_chat_secret_key"))
    return Fernet(key)

def encrypt_message(message, cipher):
    """Mesajı şifreler."""
    if not ENCRYPTION_AVAILABLE or cipher is None:
        return message
    return cipher.encrypt(message.encode('utf-8')).decode('utf-8')

def decrypt_message(encrypted_message, cipher):
    """Şifrelenmiş mesajı çözer."""
    if not ENCRYPTION_AVAILABLE or cipher is None:
        return encrypted_message
    try:
        return cipher.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')
    except:
        return encrypted_message  # Şifre çözülemezse orijinal mesajı döndür

def broadcast(room_id, message, sender_conn):
    """Bir odadaki herkese şifrelenmiş mesaj gönderir."""
    if room_id in rooms:
        # Mesajı şifrele
        cipher = rooms[room_id]["cipher"]
        encrypted_message = encrypt_message(message, cipher)
        message_with_newline = encrypted_message + '\n'
        
        for client_conn in rooms[room_id]["clients"]:
            if client_conn != sender_conn:
                try:
                    client_conn.send(message_with_newline.encode('utf-8'))
                except:
                    remove_client(client_conn)

def remove_client(conn):
    """Bir istemciyi odalardan ve sunucudan kaldırır."""
    for room_id, room_data in list(rooms.items()):
        if conn in room_data["clients"]:
            username = room_data["usernames"].get(conn, "Bilinmeyen")
            room_data["clients"].remove(conn)
            if conn in room_data["usernames"]:
                del room_data["usernames"][conn]
            
            if not room_data["clients"]:
                # Sunucuyu çalıştıran kişi odadan ayrılırsa odayı kapatma
                is_host = room_data.get("host_conn") == conn
                if not is_host:
                    del rooms[room_id]
                    print(f"Oda {room_id} boşaldığı için kapatıldı.")
                else:
                    # Sunucu sahibi ayrıldı ama oda kalabilir (isteğe bağlı)
                    print(f"Sunucu sahibi {username} odadan ayrıldı.")

            else:
                broadcast(room_id, f"Sistem: {username} odadan ayrıldı.", None)
            break
    conn.close()

def handle_client(conn, addr):
    """Her bir istemci bağlantısını yönetir."""
    print(f"Yeni bağlantı: {addr}")
    current_room = None
    username = None
    cipher = None

    try:
        while True:
            data = conn.recv(1024).decode('utf-8').strip()
            if not data:
                break

            if data.startswith("__create_room__"):
                _, room_name, req_username = data.split(":", 2)
                room_id = generate_room_id()
                while room_id in rooms:
                    room_id = generate_room_id()
                
                # Kullanıcı adı kontrolü (yeni oda için her zaman müsait)
                final_username = req_username
                
                # Oda için şifreleme anahtarı oluştur
                if ENCRYPTION_AVAILABLE:
                    room_cipher = generate_key_from_room_id(room_id)
                else:
                    room_cipher = None
                
                rooms[room_id] = {
                    "name": room_name,
                    "clients": [conn],
                    "usernames": {conn: final_username},
                    "host_conn": conn, # Odayı kuran sunucu sahibi
                    "cipher": room_cipher
                }
                current_room = room_id
                username = final_username
                cipher = room_cipher
                conn.send(f"ROOM_CREATED:{room_id}:{room_name}:{final_username}\n".encode('utf-8'))

            elif data.startswith("__join_room__"):
                _, room_id, req_username = data.split(":", 2)
                if room_id in rooms:
                    # Kullanıcı adı müsait mi kontrol et
                    if check_username_availability(room_id, req_username):
                        final_username = req_username
                        rooms[room_id]["clients"].append(conn)
                        rooms[room_id]["usernames"][conn] = final_username
                        current_room = room_id
                        username = final_username
                        cipher = rooms[room_id]["cipher"]
                        conn.send(f"JOIN_SUCCESS:{room_id}:{rooms[room_id]['name']}:{final_username}\n".encode('utf-8'))
                        broadcast(current_room, f"Sistem: {username} odaya katıldı.", conn)
                    else:
                        # Kullanıcı adı zaten mevcut, alternatif öner
                        suggested_username = suggest_alternative_username(room_id, req_username)
                        conn.send(f"USERNAME_TAKEN:{req_username}:{suggested_username}\n".encode('utf-8'))
                else:
                    conn.send("JOIN_ERROR:Oda bulunamadı.\n".encode('utf-8'))
            
            elif data.startswith("__check_room__"):
                # Oda varlık kontrolü
                _, room_id = data.split(":", 1)
                if room_id in rooms:
                    room_name = rooms[room_id]["name"]
                    user_count = len(rooms[room_id]["clients"])
                    conn.send(f"ROOM_EXISTS:{room_id}:{room_name}:{user_count}\n".encode('utf-8'))
                else:
                    conn.send(f"ROOM_NOT_FOUND:{room_id}\n".encode('utf-8'))
            
            elif data.startswith("__check_room_name__"):
                # Oda ismi kontrolü
                _, requested_room_name = data.split(":", 1)
                room_name_exists = False
                existing_room_id = None
                
                # Tüm odalarda aynı isim var mı kontrol et
                for rid, room_data in rooms.items():
                    if room_data["name"].lower() == requested_room_name.lower():
                        room_name_exists = True
                        existing_room_id = rid
                        break
                
                if room_name_exists:
                    user_count = len(rooms[existing_room_id]["clients"])
                    conn.send(f"ROOM_NAME_EXISTS:{requested_room_name}:{existing_room_id}:{user_count}\n".encode('utf-8'))
                else:
                    conn.send(f"ROOM_NAME_AVAILABLE:{requested_room_name}\n".encode('utf-8'))
            
            elif data.startswith("__join_with_new_username__"):
                _, room_id, new_username = data.split(":", 2)
                if room_id in rooms:
                    if check_username_availability(room_id, new_username):
                        rooms[room_id]["clients"].append(conn)
                        rooms[room_id]["usernames"][conn] = new_username
                        current_room = room_id
                        username = new_username
                        cipher = rooms[room_id]["cipher"]
                        conn.send(f"JOIN_SUCCESS:{room_id}:{rooms[room_id]['name']}:{new_username}\n".encode('utf-8'))
                        broadcast(current_room, f"Sistem: {username} odaya katıldı.", conn)
                    else:
                        # Hala mevcut, yeni alternatif öner
                        suggested_username = suggest_alternative_username(room_id, new_username)
                        conn.send(f"USERNAME_TAKEN:{new_username}:{suggested_username}\n".encode('utf-8'))
                else:
                    conn.send("JOIN_ERROR:Oda bulunamadı.\n".encode('utf-8'))

            elif current_room and username and cipher:
                if data == "/quit":
                    break
                
                elif data == "/leave":
                    # Odadan çıkma komutu - oda sahibi vs katılımcı kontrolü
                    is_host = rooms[current_room].get("host_conn") == conn
                    
                    if is_host:
                        # Oda sahibi çıkış yapmak istiyor
                        warning_msg = "⚠️  Bu odadan çıkarsanız, odadaki tüm kullanıcılar da otomatik olarak çıkarılacak ve oda kapanacaktır. Devam etmek istiyor musunuz? (evet/hayır)"
                        if ENCRYPTION_AVAILABLE and cipher:
                            encrypted_warning = encrypt_message(warning_msg, cipher)
                            conn.send(f"HOST_LEAVE_CONFIRM:{encrypted_warning}\n".encode('utf-8'))
                        else:
                            conn.send(f"HOST_LEAVE_CONFIRM:{warning_msg}\n".encode('utf-8'))
                    else:
                        # Normal katılımcı çıkış yapmak istiyor
                        warning_msg = "⚠️  Odadan çıkmak üzeresiniz. Devam etmek istiyor musunuz? (evet/hayır)"
                        if ENCRYPTION_AVAILABLE and cipher:
                            encrypted_warning = encrypt_message(warning_msg, cipher)
                            conn.send(f"USER_LEAVE_CONFIRM:{encrypted_warning}\n".encode('utf-8'))
                        else:
                            conn.send(f"USER_LEAVE_CONFIRM:{warning_msg}\n".encode('utf-8'))
                
                elif data.startswith("__leave_confirmed__"):
                    # Çıkış onaylandı
                    _, confirm_type = data.split(":", 1)
                    
                    if confirm_type == "host":
                        # Oda sahibi onayladı - tüm odayı kapat
                        if current_room in rooms:
                            # Önce diğer kullanıcılara haber ver
                            broadcast(current_room, f"Sistem: Oda sahibi {username} odayı kapattı. Tüm kullanıcılar çıkarılıyor.", conn)
                            
                            # Tüm kullanıcıları çıkar
                            for client_conn in list(rooms[current_room]["clients"]):
                                if client_conn != conn:
                                    try:
                                        goodbye_msg = "Sistem: Oda kapatıldı. Bağlantı sonlandırılıyor."
                                        if ENCRYPTION_AVAILABLE and cipher:
                                            encrypted_goodbye = encrypt_message(goodbye_msg, cipher)
                                            client_conn.send(f"ROOM_CLOSED:{encrypted_goodbye}\n".encode('utf-8'))
                                        else:
                                            client_conn.send(f"ROOM_CLOSED:{goodbye_msg}\n".encode('utf-8'))
                                        client_conn.close()
                                    except:
                                        pass
                            
                            # Odayı sil
                            del rooms[current_room]
                            print(f"Oda {current_room} oda sahibi tarafından kapatıldı.")
                        
                        # Oda sahibini de çıkar
                        goodbye_msg = "Sistem: Oda başarıyla kapatıldı. Bağlantı sonlandırılıyor."
                        if ENCRYPTION_AVAILABLE and cipher:
                            encrypted_goodbye = encrypt_message(goodbye_msg, cipher)
                            conn.send(f"LEAVE_SUCCESS:{encrypted_goodbye}\n".encode('utf-8'))
                        else:
                            conn.send(f"LEAVE_SUCCESS:{goodbye_msg}\n".encode('utf-8'))
                        break
                        
                    elif confirm_type == "user":
                        # Normal kullanıcı onayladı - sadece kendisini çıkar
                        broadcast(current_room, f"Sistem: {username} odadan ayrıldı.", conn)
                        remove_client(conn)
                        
                        goodbye_msg = "Sistem: Odadan başarıyla çıktınız. Bağlantı sonlandırılıyor."
                        if ENCRYPTION_AVAILABLE and cipher:
                            encrypted_goodbye = encrypt_message(goodbye_msg, cipher)
                            conn.send(f"LEAVE_SUCCESS:{encrypted_goodbye}\n".encode('utf-8'))
                        else:
                            conn.send(f"LEAVE_SUCCESS:{goodbye_msg}\n".encode('utf-8'))
                        break
                
                elif data.startswith("__leave_cancelled__"):
                    # Çıkış iptal edildi
                    cancel_msg = "Sistem: Odadan çıkış iptal edildi."
                    if ENCRYPTION_AVAILABLE and cipher:
                        encrypted_cancel = encrypt_message(cancel_msg, cipher)
                        conn.send(f"{encrypted_cancel}\n".encode('utf-8'))
                    else:
                        conn.send(f"{cancel_msg}\n".encode('utf-8'))
                
                elif data == "/users":
                    user_list = ", ".join(rooms[current_room]["usernames"].values())
                    response_message = f"Sistem: Odadaki kullanıcılar: {user_list}"
                    if ENCRYPTION_AVAILABLE and cipher:
                        encrypted_response = encrypt_message(response_message, cipher)
                        conn.send(f"{encrypted_response}\n".encode('utf-8'))
                    else:
                        conn.send(f"{response_message}\n".encode('utf-8'))

                elif data == "/help":
                    response_message = "Sistem: Kullanılabilir komutlar: /users, /leave, /quit, /help"
                    if ENCRYPTION_AVAILABLE and cipher:
                        encrypted_response = encrypt_message(response_message, cipher)
                        conn.send(f"{encrypted_response}\n".encode('utf-8'))
                    else:
                        conn.send(f"{response_message}\n".encode('utf-8'))
                
                elif not data.startswith('/') and not data.startswith('__'):
                    # Gelen mesajı şifre çöz (eğer şifreleme mevcut ise)
                    if ENCRYPTION_AVAILABLE and cipher:
                        try:
                            decrypted_message = decrypt_message(data, cipher)
                            broadcast(current_room, f"{username}: {decrypted_message}", conn)
                        except Exception:
                            # Şifre çözülemezse orijinal mesajı kullan
                            broadcast(current_room, f"{username}: {data}", conn)
                    else:
                        broadcast(current_room, f"{username}: {data}", conn)
    
    except (ConnectionResetError, UnicodeDecodeError):
        pass
    finally:
        if current_room and conn in rooms.get(current_room, {}).get("clients", []):
            remove_client(conn)
        print(f"Bağlantı sonlandırıldı: {addr}")
        conn.close()

def start_server(host_ip, port=None):
    """Sunucuyu dinlemeye başlatır ve kullanılan portu döndürür."""
    if port is None:
        port = find_available_port()
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host_ip, port))
    server.listen()
    
    # Yerel IP adresini otomatik bul
    local_ip = get_local_ip()
    
    print(f"🚀 Sunucu {host_ip}:{port} adresinde başlatıldı ve bağlantılar dinleniyor.")
    print(f"📋 Diğer kullanıcılar bu bilgilerle bağlanabilir:")
    print(f"   python3 client.py --connect {local_ip}:{port}")
    print()

    # Port bilgisini paylaş (thread'den erişim için global)
    global SERVER_PORT
    SERVER_PORT = port

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        thread.start()

# ==============================================================================
# İSTEMCİ TARAFI MANTIĞI
# ==============================================================================

stop_thread = False
original_termios_settings = None
input_lock = threading.Lock()
current_input = ""
client_cipher = None  # İstemci tarafında şifreleme anahtarı
current_client_socket = None  # Global client socket erişimi

def setup_terminal():
    """Terminali anlık karakter girişi için ayarlar."""
    global original_termios_settings
    if sys.stdin.isatty():
        original_termios_settings = termios.tcgetattr(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())

def restore_terminal():
    """Terminali orijinal ayarlarına döndürür."""
    if original_termios_settings:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, original_termios_settings)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def redraw_line(message):
    """Gelen mesajı yazdırır ve kullanıcının mevcut girdisini yeniden çizer."""
    global client_cipher, current_input
    with input_lock:
        # Özel mesaj türlerini kontrol et (basit gösterim)
        if message.startswith('HOST_LEAVE_CONFIRM:') or message.startswith('USER_LEAVE_CONFIRM:'):
            msg_type, content = message.split(':', 1)
            
            # Şifreli ise çöz
            if ENCRYPTION_AVAILABLE and client_cipher:
                try:
                    decoded_content = decrypt_message(content, client_cipher)
                except:
                    decoded_content = content
            else:
                decoded_content = content
            
            sys.stdout.write('\r\x1b[K' + decoded_content + '\n')
            sys.stdout.write("Yanıtınız (evet/hayır): ")
            sys.stdout.flush()
            return msg_type  # Özel handling gerekiyor
            
        elif message.startswith('ROOM_CLOSED:') or message.startswith('LEAVE_SUCCESS:'):
            _, content = message.split(':', 1)
            if ENCRYPTION_AVAILABLE and client_cipher:
                try:
                    decoded_content = decrypt_message(content, client_cipher)
                except:
                    decoded_content = content
            else:
                decoded_content = content
            
            sys.stdout.write('\r\x1b[K' + decoded_content + '\n')
            if message.startswith('ROOM_CLOSED:'):
                sys.stdout.write("Çıkmak için herhangi bir tuşa basın...")
            sys.stdout.flush()
            return "TERMINATE"
        
        # Normal mesaj işleme
        if ENCRYPTION_AVAILABLE and client_cipher and not message.startswith('ROOM_') and not message.startswith('JOIN_'):
            try:
                decrypted_message = decrypt_message(message, client_cipher)
                sys.stdout.write('\r\x1b[K' + decrypted_message + '\n')
            except Exception:
                sys.stdout.write('\r\x1b[K' + message + '\n')
        else:
            sys.stdout.write('\r\x1b[K' + message + '\n')
        
        sys.stdout.write(f"Siz: {current_input}")
        sys.stdout.flush()

def receive_messages(client_socket):
    global stop_thread, current_client_socket
    current_client_socket = client_socket
    buffer = ""
    pending_leave_confirmation = None
    
    while not stop_thread:
        try:
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                break
            buffer += data
            while '\n' in buffer:
                message, buffer = buffer.split('\n', 1)
                
                # Özel mesaj türlerini kontrol et
                special_result = redraw_line(message)
                
                if special_result == "TERMINATE":
                    stop_thread = True
                    break
                elif special_result in ["HOST_LEAVE_CONFIRM", "USER_LEAVE_CONFIRM"]:
                    pending_leave_confirmation = special_result
                    
                    # Terminal modunu geçici olarak normal yap
                    restore_terminal()
                    
                    # Kullanıcı yanıtını al
                    try:
                        response = input().strip().lower()
                        
                        if response in ['evet', 'e', 'yes', 'y']:
                            # Onaylandı
                            confirm_type = "host" if special_result == "HOST_LEAVE_CONFIRM" else "user"
                            client_socket.send(f"__leave_confirmed__:{confirm_type}".encode('utf-8'))
                            print("✅ Çıkış onaylandı, işlem gerçekleştiriliyor...")
                        else:
                            # İptal edildi
                            client_socket.send("__leave_cancelled__:user".encode('utf-8'))
                            print("❌ Çıkış iptal edildi.")
                    except:
                        # Hata durumunda iptal et
                        client_socket.send("__leave_cancelled__:user".encode('utf-8'))
                    
                    # Terminal modunu tekrar ayarla
                    setup_terminal()
                    
                    # Input line'ı yeniden çiz
                    with input_lock:
                        sys.stdout.write(f"Siz: {current_input}")
                        sys.stdout.flush()
                    
                    pending_leave_confirmation = None
        except:
            break

def start_client(host_ip, port=DEFAULT_PORT, show_welcome=True):
    """İstemciyi başlatır ve sunucuya bağlar."""
    global stop_thread, current_input, client_cipher, current_client_socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    current_client_socket = client
    
    try:
        client.connect((host_ip, port))
    except ConnectionRefusedError:
        print(f"Sunucuya bağlanılamadı ({host_ip}:{port}). IP adresinin ve portun doğru olduğundan ve sunucunun çalıştığından emin olun.")
        return
    except socket.gaierror:
        print(f"'{host_ip}' adresi çözümlenemedi. Geçerli bir IP adresi girin.")
        return

    # --- Başlangıç Ayarları ---
    if show_welcome:
        clear_screen()
        print("Terminal Chat'e Hoş Geldiniz!")
    
    choice = input("1. Yeni Oda Oluştur\n2. Odaya Katıl\n> ")
    
    current_room_id = None  # Odaya katılım için room_id'yi sakla
    username = None
    
    if choice == '1':
        # Önce oda adı varlığını kontrol et
        room_name_req = input("Oda adı: ")
        print("🔍 Oda adı kontrol ediliyor...")
        client.send(f"__check_room_name__:{room_name_req}".encode('utf-8'))
        
        # Oda ismi kontrol yanıtını bekle
        try:
            room_name_check_response = client.recv(1024).decode('utf-8').strip()
            
            if room_name_check_response.startswith("ROOM_NAME_AVAILABLE"):
                _, available_room_name = room_name_check_response.split(':', 1)
                print(f"✅ Oda adı '{available_room_name}' müsait!")
                print()
                
                # Oda adı müsait, kullanıcı adını sor
                username = input("Kullanıcı adınız: ")
                client.send(f"__create_room__:{room_name_req}:{username}".encode('utf-8'))
                
            elif room_name_check_response.startswith("ROOM_NAME_EXISTS"):
                _, existing_room_name, existing_room_id, user_count = room_name_check_response.split(':', 3)
                print(f"❌ '{existing_room_name}' adında oda zaten mevcut!")
                print(f"📝 Mevcut oda ID'si: {existing_room_id}")
                print(f"👥 Aktif kullanıcı sayısı: {user_count}")
                print()
                print("💡 Seçenekleriniz:")
                print("   1. Farklı bir oda adı ile yeni oda oluşturun")
                print(f"   2. Mevcut odaya katılın (Oda ID: {existing_room_id})")
                client.close()
                return
            else:
                print(f"Beklenmeyen sunucu yanıtı: {room_name_check_response}")
                client.close()
                return
                
        except Exception as e:
            print(f"Oda adı kontrol hatası: {e}")
            client.close()
            return
    elif choice == '2':
        # Önce oda varlığını kontrol et
        current_room_id = input("Oda ID'si: ")
        print("🔍 Oda kontrol ediliyor...")
        client.send(f"__check_room__:{current_room_id}".encode('utf-8'))
        
        # Oda kontrol yanıtını bekle
        try:
            room_check_response = client.recv(1024).decode('utf-8').strip()
            
            if room_check_response.startswith("ROOM_EXISTS"):
                _, room_id, room_name, user_count = room_check_response.split(':', 3)
                print(f"✅ Oda bulundu!")
                print(f"📝 Oda adı: '{room_name}'")
                print(f"👥 Aktif kullanıcı sayısı: {user_count}")
                print()
                
                # Oda mevcut, kullanıcı adını sor
                username = input("Kullanıcı adınız: ")
                client.send(f"__join_room__:{current_room_id}:{username}".encode('utf-8'))
                
            elif room_check_response.startswith("ROOM_NOT_FOUND"):
                _, room_id = room_check_response.split(':', 1)
                print(f"❌ Oda '{room_id}' bulunamadı!")
                print("💡 Lütfen doğru oda ID'sini kontrol edin veya yeni bir oda oluşturun.")
                client.close()
                return
            else:
                print(f"Beklenmeyen sunucu yanıtı: {room_check_response}")
                client.close()
                return
                
        except Exception as e:
            print(f"Oda kontrol hatası: {e}")
            client.close()
            return
    else:
        print("Geçersiz seçim.")
        client.close()
        return

    # Sunucu yanıtını işle (kullanıcı adı çakışması durumunu da handle et)
    final_username = username
    room_id = None
    room_name = None
    
    # Sadece normal join işlemleri için yanıt bekle (oda kontrolü zaten yapıldı)
    if (choice == '1' and username) or (choice == '2' and username):  # Başarılı oda oluşturma veya oda katılımı
        while True:
            try:
                response = client.recv(1024).decode('utf-8').strip()
                
                if "ROOM_CREATED" in response or "JOIN_SUCCESS" in response:
                    _, room_id, room_name, final_username = response.split(':', 3)
                    break  # Başarılı giriş
                    
                elif "USERNAME_TAKEN" in response:
                    _, taken_username, suggested_username = response.split(':', 2)
                    print(f"\n❌ Kullanıcı adı '{taken_username}' zaten mevcut!")
                    print(f"💡 Önerilen alternatif: '{suggested_username}'")
                    
                    new_choice = input("1. Önerilen adı kullan\n2. Farklı bir ad gir\n> ")
                    if new_choice == '1':
                        new_username = suggested_username
                    else:
                        new_username = input("Yeni kullanıcı adınız: ")
                    
                    # Tekrar deneme - room_id'yi kullan
                    client.send(f"__join_with_new_username__:{current_room_id}:{new_username}".encode('utf-8'))
                    
                elif "JOIN_ERROR" in response:
                    error_msg = response.split(':', 1)[1]
                    print(f"Giriş hatası: {error_msg}")
                    client.close()
                    return
                    
                else:
                    print(f"Bilinmeyen yanıt: {response}")
                    client.close()
                    return
                    
            except Exception as e:
                print(f"Sunucu hatası: {e}")
                client.close()
                return
    else:
        # Hata durumu - oda/oda adı çakışması
        print("Bağlantı sonlandırılıyor.")
        client.close()
        return
    
    # Başarılı giriş sonrası ayarlar
    if ENCRYPTION_AVAILABLE:
        client_cipher = generate_key_from_room_id(room_id)
    else:
        client_cipher = None
    
    clear_screen()
    print(f"✅ Odaya başarıyla giriş yapıldı!")
    print(f"📝 Oda: '{room_name}' (ID: {room_id})")
    print(f"👤 Kullanıcı adınız: '{final_username}'")
    
    if ENCRYPTION_AVAILABLE and client_cipher:
        print("🔒 Mesajlarınız şifrelenmiş olarak gönderilecek!")
    else:
        print("⚠️  Şifreleme mevcut değil - mesajlar düz metin olarak gönderilecek!")
    print("📌 Kullanılabilir komutlar:")
    print("   /help   - Komut listesini göster")
    print("   /users  - Odadaki kullanıcıları listele")
    print("   /leave  - Odadan çık (onay ister)")
    print("   /quit   - Anında çık")
    print()
    
    # final_username'i username'e ata
    username = final_username

    # --- Sohbet Başlıyor ---
    setup_terminal()
    receive_thread = threading.Thread(target=receive_messages, args=(client,), daemon=True)
    receive_thread.start()

    sys.stdout.write(f"Siz: ")
    sys.stdout.flush()

    try:
        while not stop_thread:
            char = sys.stdin.read(1)
            with input_lock:
                if char == '\n': # Enter
                    if current_input == "/quit":
                        stop_thread = True; break
                    
                    if current_input:
                        # Özel komutları kontrol et
                        if current_input in ["/leave", "/help", "/users"]:
                            # Bu komutlar sunucudan yanıt bekler, direkt gönder
                            client.send(current_input.encode('utf-8'))
                        elif current_input.startswith('/'):
                            # Bilinmeyen komutlar
                            sys.stdout.write('\r\x1b[K' + f"Bilinmeyen komut: {current_input}. /help yazarak yardım alabilirsiniz.\n")
                        else:
                            # Normal mesaj - şifrele ve gönder (eğer şifreleme mevcut ise)
                            if ENCRYPTION_AVAILABLE and client_cipher:
                                encrypted_input = encrypt_message(current_input, client_cipher)
                                client.send(encrypted_input.encode('utf-8'))
                            else:
                                client.send(current_input.encode('utf-8'))
                            
                            # Sadece normal mesajlar için echo yap
                            my_message = f"{username}: {current_input}"
                            sys.stdout.write('\r\x1b[K' + my_message + '\n')

                    current_input = ""
                    sys.stdout.write(f"Siz: {current_input}")
                    sys.stdout.flush()

                elif char == '\x7f': # Backspace
                    current_input = current_input[:-1]
                    sys.stdout.write('\r\x1b[K' + f"Siz: {current_input}")
                    sys.stdout.flush()
                else:
                    current_input += char
                    sys.stdout.write(char)
                    sys.stdout.flush()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        stop_thread = True
        restore_terminal()
        try: client.send("/quit".encode('utf-8'))
        except: pass
        client.close()
        print("\nBağlantı sonlandırıldı.")

# ==============================================================================
# ANA ÇALIŞTIRMA BLOĞU
# ==============================================================================

if __name__ == "__main__":
    print("=== Terminal Chat ===")
    if ENCRYPTION_AVAILABLE:
        print("✅ Şifreleme modülü yüklendi - Güvenli sohbet modu aktif")
    else:
        print("⚠️  Şifreleme modülü yüklenemedi - Düz metin modu")
    print()
    
    if len(sys.argv) == 2 and sys.argv[1] == '--host':
        # Sunucu olarak çalıştır (otomatik port)
        host_ip = '0.0.0.0' # Diğerlerinin bağlanabilmesi için tüm arayüzleri dinle
        print("🔧 Sunucu modu başlatılıyor...")
        
        # Yerel IP adresini al
        local_ip = get_local_ip()
        
        # Önce müsait port bul
        try:
            selected_port = find_available_port()
            print(f"🎯 Sunucu {selected_port} portunda başlatılacak.")
        except Exception as e:
            print(f"❌ Port bulunamadı: {e}")
            sys.exit(1)
        
        # Sunucuyu arka planda başlat
        server_thread = threading.Thread(target=start_server, args=(host_ip, selected_port), daemon=True)
        server_thread.start()
        
        # Sunucunun başlatılması için kısa bir süre bekle
        import time
        time.sleep(1)
        
        print("✅ Sunucu arka planda başlatıldı.")
        print(f"📡 Yerel IP adresiniz: {local_ip}")
        print(f"🌐 Diğer kullanıcılar şu komutla bağlanabilir:")
        print(f"   python3 client.py --connect {local_ip}:{selected_port}")
        #print()
        
        # Sunucuyu başlatan kişi aynı zamanda bir istemci olarak kendisine bağlanır
        print("🔗 Kendi sunucunuza istemci olarak bağlanılıyor...")
        print()
        start_client('127.0.0.1', selected_port, show_welcome=False)

    elif len(sys.argv) == 3 and sys.argv[1] == '--host':
        # Sunucu olarak çalıştır (belirtilen port)
        try:
            custom_port = int(sys.argv[2])
            if custom_port < 1024 or custom_port > 65535:
                print("❌ Port numarası 1024-65535 aralığında olmalıdır.")
                sys.exit(1)
        except ValueError:
            print("❌ Geçersiz port numarası. Sayısal bir değer girin.")
            sys.exit(1)
        
        host_ip = '0.0.0.0'
        print(f"🔧 Sunucu modu başlatılıyor (Port: {custom_port})...")
        
        # Yerel IP adresini al
        local_ip = get_local_ip()
        
        # Belirtilen portu kontrol et
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_socket.bind(('0.0.0.0', custom_port))
            test_socket.close()
            print(f"✅ Port {custom_port} müsait!")
            selected_port = custom_port
        except OSError:
            print(f"❌ Port {custom_port} kullanımda. Farklı bir port deneyin.")
            sys.exit(1)
        
        # Sunucuyu arka planda başlat
        server_thread = threading.Thread(target=start_server, args=(host_ip, selected_port), daemon=True)
        server_thread.start()
        
        # Sunucunun başlatılması için kısa bir süre bekle
        import time
        time.sleep(1)
        
        print("✅ Sunucu arka planda başlatıldı.")
        print(f"📡 Yerel IP adresiniz: {local_ip}")
        print(f"🌐 Diğer kullanıcılar şu komutla bağlanabilir:")
        print(f"   python3 client.py --connect {local_ip}:{selected_port}")
        
        # Sunucuyu başlatan kişi aynı zamanda bir istemci olarak kendisine bağlanır
        print("🔗 Kendi sunucunuza istemci olarak bağlanılıyor...")
        print()
        start_client('127.0.0.1', selected_port, show_welcome=False)

    elif len(sys.argv) == 3 and sys.argv[1] == '--connect':
        # İstemci olarak bir sunucuya bağlan
        host_ip = sys.argv[2].split(':')[0] # IP adresini ayıkla
        port = int(sys.argv[2].split(':')[1]) if ':' in sys.argv[2] else DEFAULT_PORT
        print(f"{host_ip}:{port} adresindeki sunucuya bağlanılıyor...")
        start_client(host_ip, port)

    else:
        print("Hatalı kullanım.")
        print("Sunucu olarak başlatmak için:")
        print("  python3 client.py --host                    # Otomatik port (12345+)")
        print("  python3 client.py --host <PORT>             # Belirtilen port")
        print("Bir sunucuya bağlanmak için:")
        print("  python3 client.py --connect <IP_ADRESI>:<PORT>")

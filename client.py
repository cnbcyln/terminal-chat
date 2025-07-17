"""
Terminal Chat - Şifrelenmiş Terminal Tabanlı Sohbet Uygulaması

GitHub Repo: https://github.com/cnbcyln/terminal-chat

Hızlı Başlangıç:
================

1. Sunucu Başlatma (Pipe ile):
   curl -s https://raw.githubusercontent.com/cnbcyln/terminal-chat/main/client.py | python3 - --host
   curl -s https://raw.githubusercontent.com/cnbcyln/terminal-chat/main/client.py | python3 - --host 8080

2. Normal Kullanım (Dosya indirme):
   wget -q -O client.py https://raw.githubusercontent.com/cnbcyln/terminal-chat/main/client.py
   python3 client.py --host                    # Otomatik port
   python3 client.py --host 8080               # Özel port
   python3 client.py --connect 192.168.1.100:8080  # Bağlan

Özellikler:
===========
- 🔒 AES şifreleme (cryptography)
- 👥 Çoklu kullanıcı desteği
- 🏠 Oda sistemi (benzersiz adlar)
- 🌐 Otomatik IP tespit
- 🚪 Oda kapatma sistemi (/leave)
- 📦 Otomatik bağımlılık yükleme

Komutlar:
=========
/help   - Yardım
/users  - Kullanıcı listesi
/leave  - Oda kapatma
/quit   - Hızlı çıkış
"""

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
from datetime import datetime

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

# --- Discord Tarzı Mesaj Formatı ---
# Mesaj gruplandırma artık oda bazında tutulacak (global değişkenler kaldırıldı)

def supports_color():
    """Terminal'in renk desteği olup olmadığını kontrol eder."""
    return (hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and os.getenv("TERM") != "dumb")

def format_discord_message(username, message, room_data=None, is_system=False, check_grouping=True):
    """Discord tarzı mesaj formatı oluşturur."""
    now = datetime.now()
    current_time = (now.hour, now.minute)
    time_str = now.strftime("Bugün saat %H:%M")
    
    # Mesaj gruplandırma kontrolü - oda bazında
    should_group = False
    if check_grouping and not is_system and room_data is not None:
        # Oda bazında last_message verilerini kontrol et
        last_message_times = room_data.get("last_message_times", {})
        last_message_user = room_data.get("last_message_user", None)
        
        if username in last_message_times:
            last_time = last_message_times[username]
            if last_time == current_time and last_message_user == username:
                should_group = True
    
    # Son mesaj zamanını ve kullanıcıyı güncelle - oda bazında
    if not is_system and room_data is not None:
        if "last_message_times" not in room_data:
            room_data["last_message_times"] = {}
        room_data["last_message_times"][username] = current_time
        room_data["last_message_user"] = username
    
    # Mesaj satırlarını ayır (uzun mesajlar için)
    message_lines = message.split('\n')
    
    if should_group:
        # Aynı dakikada aynı kullanıcıdan mesaj - sadece mesaj satırları ekle
        # Terminal renk desteği kontrolü
        if supports_color():
            color = "\033[94m"  # Normal kullanıcılar mavi
            reset = "\033[0m"
        else:
            color = ""
            reset = ""
        
        # Önceki alt çizgiyi sil (bir satır yukarı çık ve sil)
        clear_previous = "\033[A\033[K\033[A"
        
        # Mesaj genişliği - varsayılan minimum 30 karakter
        content_width = 26  # 30 - 4 for borders
        
        # Mesaj satırları
        message_lines_formatted = []
        for line in message_lines:
            line_padded = line + " " * (content_width - len(line))
            formatted_line = f"{color}│{reset} {line_padded} {color}│{reset}"
            message_lines_formatted.append(formatted_line)
        
        # Yeni alt çizgi
        bottom_line = f"{color}╰" + "─" * 28 + f"╯{reset}"
        
        # Önceki alt çizgiyi sil + yeni mesaj satırları + yeni alt çizgi
        result = [clear_previous] + message_lines_formatted + [bottom_line]
        return "\n".join(result)
    
    else:
        # Yeni çerçeve - normal format
        # Header text
        header_text = f"{username} - {time_str}"
        
        # En uzun satırı bul (header veya mesaj satırları)
        max_width = max(len(header_text), max(len(line) for line in message_lines))
        
        # Minimum genişlik 30 karakter
        box_width = max(max_width + 4, 30)

        # Terminal renk desteği kontrolü
        if supports_color():
            if is_system:
                # Sistem mesajları gri
                color = "\033[90m"
                reset = "\033[0m"
            else:
                # Normal kullanıcılar mavi
                color = "\033[94m"
                reset = "\033[0m"
        else:
            color = ""
            reset = ""
        
        # Box çizimi
        # Top line: ╭─ header ─────╮ 
        header_section = f"─ {header_text} "
        remaining_dashes = box_width - len(header_section) - 2  # -2 for ╭ and ╮
        top_line = f"{color}╭{header_section}" + "─" * remaining_dashes + f"╮{reset}"
        
        # Mesaj satırları
        message_lines_formatted = []
        for line in message_lines:
            # │ message      │ 
            content_width = box_width - 4  # -4 for │ space space │
            line_padded = line + " " * (content_width - len(line))
            formatted_line = f"{color}│{reset} {line_padded} {color}│{reset}"
            message_lines_formatted.append(formatted_line)
        
        bottom_line = f"{color}╰" + "─" * (box_width - 2) + f"╯{reset}"
        
        # Tüm satırları birleştir
        result = [top_line] + message_lines_formatted + [bottom_line]
        
        return "\n".join(result)

def format_system_message(message):
    """Sistem mesajları için özel format."""
    return format_discord_message("Sistem", message, room_data=None, is_system=True)

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
            test_socket.bind(("0.0.0.0", port))
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
            test_socket.bind(("0.0.0.0", port))
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
    return "".join(random.choices(string.digits, k=4))

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
    salt = room_id.encode("utf-8").ljust(16, b"0")[:16]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(b"terminal_chat_secret_key"))
    return Fernet(key)

def encrypt_message(message, cipher):
    """Mesajı şifreler."""
    if not ENCRYPTION_AVAILABLE or cipher is None:
        return message
    return cipher.encrypt(message.encode("utf-8")).decode("utf-8")

def decrypt_message(encrypted_message, cipher):
    """Şifrelenmiş mesajı çözer."""
    if not ENCRYPTION_AVAILABLE or cipher is None:
        return encrypted_message
    try:
        return cipher.decrypt(encrypted_message.encode("utf-8")).decode("utf-8")
    except:
        return encrypted_message  # Şifre çözülemezse orijinal mesajı döndür

def broadcast(room_id, message, sender_conn):
    """Bir odadaki herkese şifrelenmiş mesaj gönderir."""
    room = rooms.get(room_id)
    if not room:
        return
    cipher = room["cipher"]
    encrypted_message = encrypt_message(message, cipher)
    message_with_newline = encrypted_message + "\n"

    for client_conn in list(room["clients"]):
        if client_conn != sender_conn:
            try:
                client_conn.send(message_with_newline.encode("utf-8"))
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
                # Oda silinmişse tekrar broadcast yapma
                if room_id in rooms:
                    formatted_message = format_system_message(f"{username} odadan ayrıldı.")
                    broadcast(room_id, formatted_message, None)
            break
    conn.close()

def handle_client(conn, addr):
    """Her bir istemci bağlantısını yönetir."""
    current_room = None
    username = None
    cipher = None

    try:
        while True:
            try:
                data = conn.recv(1024).decode("utf-8").strip()
            except OSError:
                # Bağlantı kapatıldıysa döngüden çık
                break
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
                    "host_conn": conn,  # Odayı kuran sunucu sahibi
                    "cipher": room_cipher,
                }
                current_room = room_id
                username = final_username
                cipher = room_cipher
                conn.send(
                    f"ROOM_CREATED:{room_id}:{room_name}:{final_username}\n".encode(
                        "utf-8"
                    )
                )

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
                        conn.send(
                            f"JOIN_SUCCESS:{room_id}:{rooms[room_id]['name']}:{final_username}\n".encode(
                                "utf-8"
                            )
                        )
                        formatted_message = format_system_message(
                            f"{username} odaya katıldı."
                        )
                        broadcast(current_room, formatted_message, conn)
                    else:
                        # Kullanıcı adı zaten mevcut, alternatif öner
                        suggested_username = suggest_alternative_username(
                            room_id, req_username
                        )
                        conn.send(
                            f"USERNAME_TAKEN:{req_username}:{suggested_username}\n".encode(
                                "utf-8"
                            )
                        )
                else:
                    conn.send("JOIN_ERROR:Oda bulunamadı.\n".encode("utf-8"))

            elif data.startswith("__check_room__"):
                # Oda varlık kontrolü
                _, room_id = data.split(":", 1)
                if room_id in rooms:
                    room_name = rooms[room_id]["name"]
                    user_count = len(rooms[room_id]["clients"])
                    conn.send(
                        f"ROOM_EXISTS:{room_id}:{room_name}:{user_count}\n".encode(
                            "utf-8"
                        )
                    )
                else:
                    conn.send(f"ROOM_NOT_FOUND:{room_id}\n".encode("utf-8"))

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
                    conn.send(
                        f"ROOM_NAME_EXISTS:{requested_room_name}:{existing_room_id}:{user_count}\n".encode(
                            "utf-8"
                        )
                    )
                else:
                    conn.send(
                        f"ROOM_NAME_AVAILABLE:{requested_room_name}\n".encode("utf-8")
                    )

            elif data.startswith("__list_rooms__"):
                # Oda listesi komutu
                if not rooms:
                    conn.send("ROOM_LIST_EMPTY:\n".encode("utf-8"))
                else:
                    room_list = []
                    for room_id, room_data in rooms.items():
                        room_name = room_data["name"]
                        user_count = len(room_data["clients"])
                        room_list.append(f"{room_name}:{room_id}:{user_count}")

                    rooms_data = "|".join(room_list)
                    conn.send(f"ROOM_LIST:{rooms_data}\n".encode("utf-8"))

            elif data.startswith("__join_with_new_username__"):
                _, room_id, new_username = data.split(":", 2)
                if room_id in rooms:
                    if check_username_availability(room_id, new_username):
                        rooms[room_id]["clients"].append(conn)
                        rooms[room_id]["usernames"][conn] = new_username
                        current_room = room_id
                        username = new_username
                        cipher = rooms[room_id]["cipher"]
                        conn.send(
                            f"JOIN_SUCCESS:{room_id}:{rooms[room_id]['name']}:{new_username}\n".encode(
                                "utf-8"
                            )
                        )
                        formatted_message = format_system_message(
                            f"{username} odaya katıldı."
                        )
                        broadcast(current_room, formatted_message, conn)
                    else:
                        # Hala mevcut, yeni alternatif öner
                        suggested_username = suggest_alternative_username(
                            room_id, new_username
                        )
                        conn.send(
                            f"USERNAME_TAKEN:{new_username}:{suggested_username}\n".encode(
                                "utf-8"
                            )
                        )
                else:
                    conn.send("JOIN_ERROR:Oda bulunamadı.\n".encode("utf-8"))

            elif current_room and username and cipher:
                if data == "/quit":
                    break

                elif data == "/leave":
                    # Odadan çıkma komutu - oda sahibi vs katılımcı kontrolü
                    is_host = rooms[current_room].get("host_conn") == conn

                    if is_host:
                        # Oda sahibi çıkış yapmak istiyor
                        warning_msg = "⚠️  Bu odadan çıkarsanız, odadaki tüm kullanıcılar da otomatik olarak çıkarılacak ve oda kapanacaktır. Devam etmek istiyor musunuz? (evet/e/hayır/h)"
                        if ENCRYPTION_AVAILABLE and cipher:
                            encrypted_warning = encrypt_message(warning_msg, cipher)
                            conn.send(
                                f"HOST_LEAVE_CONFIRM:{encrypted_warning}\n".encode(
                                    "utf-8"
                                )
                            )
                        else:
                            conn.send(
                                f"HOST_LEAVE_CONFIRM:{warning_msg}\n".encode("utf-8")
                            )
                    else:
                        # Normal katılımcı çıkış yapmak istiyor
                        warning_msg = "⚠️  Odadan çıkmak üzeresiniz. Devam etmek istiyor musunuz? (evet/e/hayır/h)"
                        if ENCRYPTION_AVAILABLE and cipher:
                            encrypted_warning = encrypt_message(warning_msg, cipher)
                            conn.send(
                                f"USER_LEAVE_CONFIRM:{encrypted_warning}\n".encode(
                                    "utf-8"
                                )
                            )
                        else:
                            conn.send(
                                f"USER_LEAVE_CONFIRM:{warning_msg}\n".encode("utf-8")
                            )

                elif data.startswith("__leave_confirmed__"):
                    # Çıkış onaylandı
                    _, confirm_type = data.split(":", 1)

                    if confirm_type == "host":
                        # Oda sahibi onayladı - tüm odayı kapat
                        if current_room in rooms:
                            # Önce diğer kullanıcılara haber ver
                            formatted_message = format_system_message(
                                f"Oda sahibi {username} odayı kapattı. Tüm kullanıcılar çıkarılıyor."
                            )
                            broadcast(current_room, formatted_message, conn)

                            import time
                            time.sleep(3)  # Mesajların istemcilere ulaşması için kısa bekleme

                            # Tüm kullanıcıları çıkar
                            for client_conn in list(rooms[current_room]["clients"]):
                                if client_conn != conn:
                                    try:
                                        goodbye_msg = "Sistem: Oda kapatıldı. Bağlantı sonlandırılıyor."
                                        if ENCRYPTION_AVAILABLE and cipher:
                                            encrypted_goodbye = encrypt_message(
                                                goodbye_msg, cipher
                                            )
                                            client_conn.send(
                                                f"ROOM_CLOSED:{encrypted_goodbye}\n".encode(
                                                    "utf-8"
                                                )
                                            )
                                        else:
                                            client_conn.send(
                                                f"ROOM_CLOSED:{goodbye_msg}\n".encode(
                                                    "utf-8"
                                                )
                                            )
                                        client_conn.close()
                                    except:
                                        pass

                            # Odayı sil
                            del rooms[current_room]
                            print(
                                f"Oda {current_room} oda sahibi tarafından kapatıldı."
                            )

                        # Oda sahibini de çıkar
                        goodbye_msg = (
                            "Sistem: Oda başarıyla kapatıldı. Bağlantı sonlandırılıyor."
                        )
                        if ENCRYPTION_AVAILABLE and cipher:
                            encrypted_goodbye = encrypt_message(goodbye_msg, cipher)
                            conn.send(
                                f"LEAVE_SUCCESS:{encrypted_goodbye}\n".encode("utf-8")
                            )
                        else:
                            conn.send(f"LEAVE_SUCCESS:{goodbye_msg}\n".encode("utf-8"))
                        break

                    elif confirm_type == "user":
                        # Normal kullanıcı onayladı - sadece kendisini çıkar

                        # Önce mesajı gönder
                        goodbye_msg = "Sistem: Odadan başarıyla çıktınız. Bağlantı sonlandırılıyor."
                        if ENCRYPTION_AVAILABLE and cipher:
                            encrypted_goodbye = encrypt_message(goodbye_msg, cipher)
                            conn.send(
                                f"LEAVE_SUCCESS:{encrypted_goodbye}\n".encode("utf-8")
                            )
                        else:
                            conn.send(f"LEAVE_SUCCESS:{goodbye_msg}\n".encode("utf-8"))

                        # remove_client zaten broadcast yapacak, tekrar yapmaya gerek yok
                        remove_client(conn)
                        break

                elif data.startswith("__leave_cancelled__"):
                    # Çıkış iptal edildi
                    cancel_msg = format_system_message("Odadan çıkış iptal edildi.")
                    if ENCRYPTION_AVAILABLE and cipher:
                        encrypted_cancel = encrypt_message(cancel_msg, cipher)
                        conn.send(f"{encrypted_cancel}\n".encode("utf-8"))
                    else:
                        conn.send(f"{cancel_msg}\n".encode("utf-8"))

                elif data == "/users":
                    user_list = ", ".join(rooms[current_room]["usernames"].values())
                    response_message = format_system_message(
                        f"Odadaki kullanıcılar: {user_list}"
                    )
                    if ENCRYPTION_AVAILABLE and cipher:
                        encrypted_response = encrypt_message(response_message, cipher)
                        conn.send(f"{encrypted_response}\n".encode("utf-8"))
                    else:
                        conn.send(f"{response_message}\n".encode("utf-8"))

                elif data == "/help":
                    response_message = format_system_message(
                        "Kullanılabilir komutlar: /users, /leave, /quit, /help"
                    )
                    if ENCRYPTION_AVAILABLE and cipher:
                        encrypted_response = encrypt_message(response_message, cipher)
                        conn.send(f"{encrypted_response}\n".encode("utf-8"))
                    else:
                        conn.send(f"{response_message}\n".encode("utf-8"))

                elif not data.startswith("/") and not data.startswith("__"):
                    # Gelen mesajı şifre çöz (eğer şifreleme mevcut ise)
                    if ENCRYPTION_AVAILABLE and cipher:
                        try:
                            decrypted_message = decrypt_message(data, cipher)
                            # Sunucu tarafında basit format - gruplandırma istemci tarafında yapılacak
                            formatted_message = f"MSG:{username}:{decrypted_message}"
                            broadcast(current_room, formatted_message, conn)
                        except Exception:
                            # Şifre çözülemezse orijinal mesajı kullan
                            formatted_message = f"MSG:{username}:{data}"
                            broadcast(current_room, formatted_message, conn)
                    else:
                        formatted_message = f"MSG:{username}:{data}"
                        broadcast(current_room, formatted_message, conn)

    except (ConnectionResetError, UnicodeDecodeError):
        pass
    finally:
        if current_room and conn in rooms.get(current_room, {}).get("clients", []):
            remove_client(conn)

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
pause_input = False  # Ana input döngüsünü geçici olarak durdurmak için
left_via_leave = False  # /leave komutu ile çıkış yapıldı mı?
original_termios_settings = None
input_lock = threading.Lock()
current_input = ""
client_cipher = None  # İstemci tarafında şifreleme anahtarı
current_client_socket = None  # Global client socket erişimi

# İstemci tarafında mesaj gruplandırması için
client_message_data = {"last_message_times": {}, "last_message_user": None }

def setup_terminal():
    """Terminali anlık karakter girişi için ayarlar."""
    global original_termios_settings
    if sys.stdin.isatty():
        original_termios_settings = termios.tcgetattr(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())

def restore_terminal():
    """Terminali orijinal ayarlarına döndürür."""
    if original_termios_settings:
        termios.tcsetattr(
            sys.stdin.fileno(), termios.TCSADRAIN, original_termios_settings
        )

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def redraw_line(message):
    """Gelen mesajı yazdırır ve kullanıcının mevcut girdisini yeniden çizer."""
    global client_cipher, current_input
    with input_lock:
        # Özel mesaj türlerini kontrol et (basit gösterim)
        if message.startswith("HOST_LEAVE_CONFIRM:") or message.startswith(
            "USER_LEAVE_CONFIRM:"
        ):
            msg_type, content = message.split(":", 1)

            # Şifreli ise çöz
            if ENCRYPTION_AVAILABLE and client_cipher:
                try:
                    decoded_content = decrypt_message(content, client_cipher)
                except:
                    decoded_content = content
            else:
                decoded_content = content

            sys.stdout.write("\r\x1b[K" + decoded_content + "\n")
            sys.stdout.write("Yanıtınız (evet/e/hayır/h): ")
            sys.stdout.flush()
            return msg_type  # Özel handling gerekiyor

        elif message.startswith("ROOM_CLOSED:") or message.startswith("LEAVE_SUCCESS:"):
            _, content = message.split(":", 1)
            if ENCRYPTION_AVAILABLE and client_cipher:
                try:
                    decoded_content = decrypt_message(content, client_cipher)
                except:
                    decoded_content = content
            else:
                decoded_content = content

            sys.stdout.write("\r\x1b[K" + decoded_content + "\n")
            if message.startswith("ROOM_CLOSED:"):
                return "RETURN_TO_MENU"
            else:
                sys.stdout.flush()
                return "TERMINATE"

        # Normal mesaj işleme
        if (
            ENCRYPTION_AVAILABLE
            and client_cipher
            and not message.startswith("ROOM_")
            and not message.startswith("JOIN_")
        ):
            try:
                decrypted_message = decrypt_message(message, client_cipher)
                # MSG: formatını kontrol et
                if decrypted_message.startswith("MSG:"):
                    _, msg_username, msg_content = decrypted_message.split(":", 2)
                    formatted_msg = format_discord_message(msg_username, msg_content, room_data=client_message_data, check_grouping=True)
                    sys.stdout.write("\r\x1b[K" + formatted_msg + "\n")
                    # Bildirim ve dock bounce ekle
                    if msg_username != os.getenv("USER", "") and msg_username != "Siz":
                        try:
                            # Terminal odakta mı kontrolü (macOS)
                            is_macos = sys.platform == "darwin"
                            if is_macos:
                                # Hangi terminalde çalıştığını bulmak için process adı
                                term_app = os.environ.get("TERM_PROGRAM", "")
                                # AppleScript ile ön planda mı kontrolü
                                script = f'tell application "System Events" to get name of first application process whose frontmost is true'
                                frontmost = subprocess.check_output(["osascript", "-e", script]).decode().strip()
                                # Eğer terminal ön planda değilse bildirim ve dock bounce
                                if not (term_app and term_app in frontmost):
                                    # Bildirim gönder
                                    subprocess.Popen(["osascript", "-e", f'display notification "{msg_content}" with title "{msg_username} - Terminal Chat"'])
                                    # Dock ikonunu zıplat
                                    subprocess.Popen(["osascript", "-e", 'tell application "System Events" to tell process "Terminal" to set frontmost to true'])
                        except Exception:
                            pass
                else:
                    sys.stdout.write("\r\x1b[K" + decrypted_message + "\n")
            except Exception:
                # MSG: formatını kontrol et
                if message.startswith("MSG:"):
                    _, msg_username, msg_content = message.split(":", 2)
                    formatted_msg = format_discord_message(msg_username, msg_content, room_data=client_message_data, check_grouping=True)
                    sys.stdout.write("\r\x1b[K" + formatted_msg + "\n")
                    # Bildirim ve dock bounce ekle
                    if msg_username != os.getenv("USER", "") and msg_username != "Siz":
                        try:
                            is_macos = sys.platform == "darwin"
                            if is_macos:
                                term_app = os.environ.get("TERM_PROGRAM", "")
                                script = f'tell application "System Events" to get name of first application process whose frontmost is true'
                                frontmost = subprocess.check_output(["osascript", "-e", script]).decode().strip()
                                if not (term_app and term_app in frontmost):
                                    subprocess.Popen(["osascript", "-e", f'display notification "{msg_content}" with title "{msg_username} - Terminal Chat"'])
                                    subprocess.Popen(["osascript", "-e", 'tell application "System Events" to tell process "Terminal" to set frontmost to true'])
                        except Exception:
                            pass
                else:
                    sys.stdout.write("\r\x1b[K" + message + "\n")
        else:
            # MSG: formatını kontrol et
            if message.startswith("MSG:"):
                _, msg_username, msg_content = message.split(":", 2)
                formatted_msg = format_discord_message(msg_username, msg_content, room_data=client_message_data, check_grouping=True)
                sys.stdout.write("\r\x1b[K" + formatted_msg + "\n")
            else:
                sys.stdout.write("\r\x1b[K" + message + "\n")

        sys.stdout.write(f"Siz: {current_input}")
        sys.stdout.flush()

def receive_messages(client_socket):
    global stop_thread, current_client_socket, pause_input, left_via_leave
    current_client_socket = client_socket
    buffer = ""
    pending_leave_confirmation = None

    while not stop_thread:
        try:
            data = client_socket.recv(1024).decode("utf-8")
            if not data:
                break
            buffer += data
            while "\n" in buffer:
                message, buffer = buffer.split("\n", 1)

                # Özel mesaj türlerini kontrol et
                special_result = redraw_line(message)

                if special_result == "TERMINATE":
                    global left_via_leave
                    left_via_leave = True  # /leave ile çıkış yapıldı
                    pause_input = False  # Input döngüsünü serbest bırak
                    stop_thread = True

                    # Thread sonlandırılacak, ana döngüde ana menü çağrılacak
                    import time

                    time.sleep(0.5)  # Mesajın görünmesi için kısa bekleme

                    # Ana input döngüsünden çıkmak için stdin'e newline gönder
                    import os

                    if os.name != "nt":  # Unix/Linux/macOS
                        os.write(sys.stdin.fileno(), b"\n")

                    break
                elif special_result == "RETURN_TO_MENU":
                    stop_thread = True
                    left_via_leave = True
                    pause_input = False
                    import time
                    time.sleep(0.5)
                    import os
                    if os.name != "nt":
                        os.write(sys.stdin.fileno(), b"\n")
                    break
                elif special_result in ["HOST_LEAVE_CONFIRM", "USER_LEAVE_CONFIRM"]:
                    pending_leave_confirmation = special_result

                    # Ana input döngüsü zaten durakladı, onay al
                    try:
                        if sys.stdin.isatty():
                            confirmation_input = ""
                            sys.stdout.flush()

                            while True:
                                char = sys.stdin.read(1)
                                if char == "\n" or char == "\r":
                                    # Enter tuşuna basıldı
                                    break
                                elif char == "\x7f":  # Backspace
                                    if confirmation_input:
                                        confirmation_input = confirmation_input[:-1]
                                        sys.stdout.write("\b \b")
                                        sys.stdout.flush()
                                else:
                                    confirmation_input += char
                                    sys.stdout.write(char)
                                    sys.stdout.flush()

                            response = confirmation_input.strip().lower()
                            print()  # Yeni satır ekle
                        else:
                            # Pipe modunda otomatik "evet" yanıtı
                            response = "evet"
                            print("evet (otomatik)")

                        if response in ["evet", "e", "yes", "y"]:
                            # Onaylandı
                            confirm_type = (
                                "host"
                                if special_result == "HOST_LEAVE_CONFIRM"
                                else "user"
                            )
                            confirm_message = f"__leave_confirmed__:{confirm_type}"
                            client_socket.send(confirm_message.encode("utf-8"))
                            print("✅ Oda kapanıyor. Ana menüye dönülüyor...")
                        else:
                            # İptal edildi
                            cancel_message = "__leave_cancelled__:user"
                            client_socket.send(cancel_message.encode("utf-8"))
                            print("❌ Çıkış iptal edildi.")
                    except EOFError:
                        # Pipe modunda EOF hatası geldiğinde otomatik onay
                        client_socket.send("__leave_confirmed__:user".encode("utf-8"))
                        print("✅ Pipe modunda otomatik çıkış onayı.")
                    except:
                        # Hata durumunda iptal et
                        client_socket.send("__leave_cancelled__:user".encode("utf-8"))

                    # Input durumunu sıfırla ve yeniden çiz
                    with input_lock:
                        current_input = ""  # Input'u sıfırla
                        sys.stdout.write(f"Siz: {current_input}")
                        sys.stdout.flush()

                    # Ana input döngüsünü tekrar başlat
                    pause_input = False

                    pending_leave_confirmation = None
        except:
            break

def safe_input(prompt, default="", is_pipe_mode=False):
    """Pipe modunda güvenli input alma fonksiyonu."""
    if is_pipe_mode:
        print(f"{prompt}{default}")
        return default
    try:
        return input(prompt)
    except EOFError:
        print(f"\nPipe modunda EOF. Varsayılan değer kullanılıyor: {default}")
        return default

def start_client(host_ip, port=DEFAULT_PORT, show_welcome=True):
    """İstemciyi başlatır ve sunucuya bağlar."""
    global stop_thread, current_input, client_cipher, current_client_socket, pause_input, left_via_leave, client_message_data

    # Global değişkenleri sıfırla
    stop_thread = False
    pause_input = False
    left_via_leave = False
    current_input = ""
    
    # İstemci mesaj gruplandırma verilerini sıfırla
    client_message_data = {
        "last_message_times": {},
        "last_message_user": None
    }

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    current_client_socket = client

    # Pipe modunda çalışıp çalışmadığını kontrol et
    is_pipe_mode = not sys.stdin.isatty()

    try:
        client.connect((host_ip, port))
    except ConnectionRefusedError:
        print(
            f"Sunucuya bağlanılamadı ({host_ip}:{port}). IP adresinin ve portun doğru olduğundan ve sunucunun çalıştığından emin olun."
        )
        sys.exit(1)
    except socket.gaierror:
        print(f"'{host_ip}' adresi çözümlenemedi. Geçerli bir IP adresi girin.")
        sys.exit(1)

    # --- Başlangıç Ayarları ---
    if show_welcome:
        clear_screen()
        print("Terminal Chat'e Hoş Geldiniz!")

    # Pipe modunda otomatik oda oluştur
    if is_pipe_mode:
        print("🔍 Pipe modunda çalıştığınız için otomatik demo oda oluşturuluyor...")
        choice = "1"  # Oda oluştur
        username = f"Host_{random.randint(1000, 9999)}"
        room_name_req = f"Demo_Oda_{random.randint(100, 999)}"
        print(f"📝 Oda adı: '{room_name_req}'")
        print(f"👤 Kullanıcı adı: '{username}'")
        print()
    else:
        print("1. Yeni Oda Oluştur")
        print("2. Odaya Katıl")
        print("3. Oda Listesi")
        choice = input("> ")

    current_room_id = None  # Odaya katılım için room_id'yi sakla
    join_room_id = None  # Username retry için room_id'yi sakla
    username = username if is_pipe_mode else None

    if choice == "1":
        if not is_pipe_mode:
            # Oda oluşturma döngüsü
            while True:
                # Önce oda adı varlığını kontrol et
                room_name_req = safe_input(
                    "Oda adı: ", f"Demo_Oda_{random.randint(100, 999)}", is_pipe_mode
                )
                print("🔍 Oda adı kontrol ediliyor...")
                client.send(f"__check_room_name__:{room_name_req}".encode("utf-8"))

                # Oda ismi kontrol yanıtını bekle
                try:
                    room_name_check_response = client.recv(1024).decode("utf-8").strip()

                    if room_name_check_response.startswith("ROOM_NAME_AVAILABLE"):
                        _, available_room_name = room_name_check_response.split(":", 1)
                        print(f"✅ Oda adı '{available_room_name}' müsait!")
                        print()

                        # Oda adı müsait, kullanıcı adını sor
                        username = safe_input(
                            "Kullanıcı adınız: ",
                            f"User_{random.randint(1000, 9999)}",
                            is_pipe_mode,
                        )
                        client.send(
                            f"__create_room__:{room_name_req}:{username}".encode(
                                "utf-8"
                            )
                        )
                        break  # Döngüden çık

                    elif room_name_check_response.startswith("ROOM_NAME_EXISTS"):
                        _, existing_room_name, existing_room_id, user_count = (
                            room_name_check_response.split(":", 3)
                        )
                        print(f"❌ '{existing_room_name}' adında oda zaten mevcut!")
                        print(f"👥 Aktif kullanıcı sayısı: {user_count}")
                        print()
                        print("💡 Seçenekleriniz:")
                        print("   1. Farklı bir oda adı ile yeni oda oluşturun")
                        print(f"   2. Mevcut odaya katılın ({existing_room_name})")

                        # Kullanıcının seçimini al
                        sub_choice = safe_input("> ", "1", is_pipe_mode)

                        if sub_choice == "1":
                            # Yeni oda adı iste ve tekrar dene
                            continue  # while döngüsünün başına dön
                        elif sub_choice == "2":
                            # Mevcut odaya katıl
                            current_room_id = (
                                existing_room_id  # room_id'yi aktarma için set et
                            )
                            join_room_id = (
                                existing_room_id  # Username retry için room_id'yi sakla
                            )
                            username = safe_input(
                                "Kullanıcı adınız: ",
                                f"User_{random.randint(1000, 9999)}",
                                is_pipe_mode,
                            )
                            client.send(
                                f"__join_room__:{existing_room_id}:{username}".encode(
                                    "utf-8"
                                )
                            )
                            break  # while döngüsünden çık
                        else:
                            print("❌ Geçersiz seçim.")
                            print("📱 Ana menüye dönülüyor...")
                            client.close()
                            # Ana menüye geri dön - yeniden başlat
                            start_client(host_ip, port, show_welcome=True)
                            return
                    else:
                        print(f"Beklenmeyen sunucu yanıtı: {room_name_check_response}")
                        client.close()
                        if not is_pipe_mode:
                            # Ana menüye geri dön - yeniden başlat
                            start_client(host_ip, port, show_welcome=True)
                        return

                except Exception as e:
                    print(f"Oda adı kontrol hatası: {e}")
                    client.close()
                    if not is_pipe_mode:
                        # Ana menüye geri dön - yeniden başlat
                        start_client(host_ip, port, show_welcome=True)
                    return
        else:
            # Pipe modunda otomatik oda oluştur (kontrol etmeden)
            room_name_req = f"Demo_Oda_{random.randint(100, 999)}"
            username = f"User_{random.randint(1000, 9999)}"
            client.send(f"__create_room__:{room_name_req}:{username}".encode("utf-8"))

    elif choice == "2":
        # Oda adı ile katılma akışı (döngülü)
        while True:
            room_name_to_join = safe_input(
                "Katılmak istediğiniz oda adı: ", "Demo_Oda", is_pipe_mode
            )
            print("🔍 Oda kontrol ediliyor...")
            client.send(f"__check_room_name__:{room_name_to_join}".encode("utf-8"))

            # Oda kontrol yanıtını bekle
            try:
                room_name_check_response = client.recv(1024).decode("utf-8").strip()

                if room_name_check_response.startswith("ROOM_NAME_EXISTS"):
                    _, existing_room_name, existing_room_id, user_count = (
                        room_name_check_response.split(":", 3)
                    )
                    print(f"✅ Oda bulundu!")
                    print(f"📝 Oda adı: '{existing_room_name}'")
                    print(f"👥 Aktif kullanıcı sayısı: {user_count}")
                    print()

                    # Oda mevcut, kullanıcı adını sor
                    current_room_id = existing_room_id  # room_id'yi set et
                    join_room_id = (
                        existing_room_id  # Username retry için room_id'yi sakla
                    )
                    username = safe_input(
                        "Kullanıcı adınız: ",
                        f"User_{random.randint(1000, 9999)}",
                        is_pipe_mode,
                    )
                    client.send(
                        f"__join_room__:{existing_room_id}:{username}".encode("utf-8")
                    )
                    break  # Başarılı, döngüden çık

                elif room_name_check_response.startswith("ROOM_NAME_AVAILABLE"):
                    _, available_room_name = room_name_check_response.split(":", 1)
                    if is_pipe_mode:
                        print(
                            f"⚠️  Oda '{available_room_name}' bulunamadı, otomatik oda oluşturuluyor..."
                        )
                        # Pipe modunda oda yoksa otomatik oda oluştur
                        choice = "1"
                        room_name_req = available_room_name
                        username = f"Host_{random.randint(1000, 9999)}"
                        print(f"📝 Yeni oda adı: '{room_name_req}'")
                        print(f"👤 Kullanıcı adı: '{username}'")
                        client.send(
                            f"__create_room__:{room_name_req}:{username}".encode(
                                "utf-8"
                            )
                        )
                        break  # Pipe modunda oda oluştur ve çık
                    else:
                        print(f"❌ '{available_room_name}' adında oda bulunamadı!")
                        print()
                        print("💡 Ne yapmak istiyorsunuz?")
                        print("1. Farklı bir oda adı deneyin")
                        print("2. Yeni oda oluşturun")
                        print("3. Ana menüye dönün")

                        user_choice = safe_input("> ", "3", is_pipe_mode)

                        if user_choice == "1":
                            # Tekrar oda adı iste - döngü başına dön
                            continue
                        elif user_choice == "2":
                            # Yeni oda oluşturmaya geç
                            choice = "1"
                            room_name_req = available_room_name
                            username = safe_input(
                                "Kullanıcı adınız: ",
                                f"User_{random.randint(1000, 9999)}",
                                is_pipe_mode,
                            )
                            client.send(
                                f"__create_room__:{room_name_req}:{username}".encode(
                                    "utf-8"
                                )
                            )
                            break  # room_name_check döngüsünden çık
                        else:
                            # Ana menüye dön
                            print("📱 Ana menüye dönülüyor...")
                            client.close()
                            # Ana menüye geri dön - yeniden başlat
                            start_client(host_ip, port, show_welcome=True)
                            return
                else:
                    print(f"Beklenmeyen sunucu yanıtı: {room_name_check_response}")
                    client.close()
                    if not is_pipe_mode:
                        # Ana menüye geri dön - yeniden başlat
                        start_client(host_ip, port, show_welcome=True)
                    return

            except Exception as e:
                print(f"Oda kontrol hatası: {e}")
                client.close()
                if not is_pipe_mode:
                    # Ana menüye geri dön - yeniden başlat
                    start_client(host_ip, port, show_welcome=True)
                return

    elif choice == "3":
        # Oda listesi göster
        print("🔍 Mevcut odalar yükleniyor...")
        client.send("__list_rooms__".encode("utf-8"))

        try:
            room_list_response = client.recv(1024).decode("utf-8").strip()

            if room_list_response.startswith("ROOM_LIST_EMPTY"):
                print("📭 Şu anda hiç aktif oda bulunmuyor.")
                if not is_pipe_mode:
                    print("💡 Yeni bir oda oluşturarak sohbete başlayabilirsiniz!")
                    print("\nAna menüye dönmek için herhangi bir tuşa basın...")
                    input()
                    client.close()
                    return "RETURN_TO_MENU"
                else:
                    # Pipe modunda otomatik oda oluştur
                    choice = "1"
                    room_name_req = f"Demo_Oda_{random.randint(100, 999)}"
                    username = f"Host_{random.randint(1000, 9999)}"
                    print(f"📝 Oda adı: '{room_name_req}'")
                    print(f"👤 Kullanıcı adı: '{username}'")
                    client.send(f"__create_room__:{room_name_req}:{username}".encode("utf-8"))
                    
            elif room_list_response.startswith("ROOM_LIST:"):
                _, rooms_data = room_list_response.split(":", 1)
                if rooms_data:
                    room_entries = rooms_data.split("|")
                    print("📋 Aktif Odalar:")
                    print("=" * 50)
                    for i, room_entry in enumerate(room_entries, 1):
                        room_name, room_id, user_count = room_entry.split(":", 2)
                        print(f"{i}. 📝 Oda Adı: {room_name}")
                        print(f"   🆔 ID: {room_id}")
                        print(f"   👥 Kullanıcı: {user_count}")
                        print("-" * 30)

                    if not is_pipe_mode:
                        # Kullanıcıya oda seçimi sun
                        print("\n💡 Seçenekleriniz:")
                        print("1. Oda adı yazarak katıl")
                        print("2. Ana menüye dön")
                        
                        user_choice = safe_input("\n> ", "2", is_pipe_mode)
                        
                        if user_choice == "1":
                            # Oda adı ile katılma işlemi
                            room_name_to_join = safe_input("Katılmak istediğiniz oda adı: ", "", is_pipe_mode)
                            if room_name_to_join.strip():
                                # Oda katılma işlemini başlat
                                print("🔍 Oda kontrol ediliyor...")
                                client.send(f"__check_room_name__:{room_name_to_join}".encode("utf-8"))
                                
                                try:
                                    room_check_response = client.recv(1024).decode("utf-8").strip()
                                    
                                    if room_check_response.startswith("ROOM_NAME_EXISTS"):
                                        _, existing_room_name, existing_room_id, user_count = room_check_response.split(":", 3)
                                        print(f"✅ Oda bulundu!")
                                        print(f"📝 Oda adı: '{existing_room_name}'")
                                        print(f"👥 Aktif kullanıcı sayısı: {user_count}")
                                        print()
                                        
                                        username = safe_input("Kullanıcı adınız: ", f"User_{random.randint(1000, 9999)}", is_pipe_mode)
                                        client.send(f"__join_room__:{existing_room_id}:{username}".encode("utf-8"))
                                        current_room_id = existing_room_id
                                        join_room_id = existing_room_id
                                        choice = "2"  # Katılım işlemine devam et
                                    else:
                                        print(f"❌ '{room_name_to_join}' adında oda bulunamadı!")
                                        print("\nAna menüye dönülüyor...")
                                        client.close()
                                        return "RETURN_TO_MENU"
                                        
                                except Exception as e:
                                    print(f"Oda kontrol hatası: {e}")
                                    client.close()
                                    return "RETURN_TO_MENU"
                            else:
                                print("❌ Geçersiz oda adı!")
                                print("\nAna menüye dönülüyor...")
                                client.close()
                                return "RETURN_TO_MENU"
                        else:
                            # Ana menüye dön
                            print("📱 Ana menüye dönülüyor...")
                            client.close()
                            return "RETURN_TO_MENU"
                    else:
                        # Pipe modunda otomatik oda oluştur
                        choice = "1"
                        room_name_req = f"Demo_Oda_{random.randint(100, 999)}"
                        username = f"Host_{random.randint(1000, 9999)}"
                        print(f"📝 Oda adı: '{room_name_req}'")
                        print(f"👤 Kullanıcı adı: '{username}'")
                        client.send(f"__create_room__:{room_name_req}:{username}".encode("utf-8"))
                else:
                    print("📭 Şu anda hiç aktif oda bulunmuyor.")
                    if not is_pipe_mode:
                        print("\nAna menüye dönmek için herhangi bir tuşa basın...")
                        input()
                        client.close()
                        return "RETURN_TO_MENU"
                    else:
                        # Pipe modunda otomatik oda oluştur
                        choice = "1"
                        room_name_req = f"Demo_Oda_{random.randint(100, 999)}"
                        username = f"Host_{random.randint(1000, 9999)}"
                        print(f"📝 Oda adı: '{room_name_req}'")
                        print(f"👤 Kullanıcı adı: '{username}'")
                        client.send(f"__create_room__:{room_name_req}:{username}".encode("utf-8"))
            else:
                print(f"Beklenmeyen sunucu yanıtı: {room_list_response}")
                if not is_pipe_mode:
                    print("\nAna menüye dönmek için herhangi bir tuşa basın...")
                    input()
                    client.close()
                    return "RETURN_TO_MENU"

        except Exception as e:
            print(f"Oda listesi hatası: {e}")
            client.close()
            if not is_pipe_mode:
                client.close()
                return "RETURN_TO_MENU"
            return

    else:
        if not is_pipe_mode:
            print("❌ Geçersiz seçim. Lütfen 1, 2 veya 3'ü seçin.")
            print("\nAna menüye dönmek için herhangi bir tuşa basın...")
            input()
            client.close()
            # Ana menüye geri dön - yeniden başlat
            start_client(host_ip, port, show_welcome=True)
        else:
            client.close()
        return

    # Sunucu yanıtını işle (kullanıcı adı çakışması durumunu da handle et)
    final_username = username
    room_id = None
    room_name = None
    join_room_id = None  # Join işlemi için kullanılan room ID'yi sakla

    # Sadece normal join işlemleri için yanıt bekle (oda kontrolü zaten yapıldı)
    if (choice == "1" and username) or (
        choice == "2" and username
    ):  # Başarılı oda oluşturma veya oda katılımı
        while True:
            try:
                response = client.recv(1024).decode("utf-8").strip()

                if "ROOM_CREATED" in response or "JOIN_SUCCESS" in response:
                    _, room_id, room_name, final_username = response.split(":", 3)
                    break  # Başarılı giriş

                elif "USERNAME_TAKEN" in response:
                    _, taken_username, suggested_username = response.split(":", 2)
                    print(f"\n❌ Kullanıcı adı '{taken_username}' zaten mevcut!")
                    print(f"💡 Önerilen alternatif: '{suggested_username}'")

                    if is_pipe_mode:
                        # Pipe modunda otomatik olarak önerilen adı kullan
                        new_username = suggested_username
                        print(f"📝 Pipe modunda otomatik seçim: '{new_username}'")
                    else:
                        new_choice = safe_input(
                            "1. Önerilen adı kullan\n2. Farklı bir ad gir\n3. Vazgeç\n> ",
                            "1",
                            is_pipe_mode,
                        )
                        if new_choice == "1":
                            new_username = suggested_username
                        elif new_choice == "2":
                            new_username = safe_input(
                                "Yeni kullanıcı adınız: ",
                                f"User_{random.randint(1000, 9999)}",
                                is_pipe_mode,
                            )
                        else:
                            # Vazgeç seçeneği - ana menüye dön
                            print("❌ Oda katılımından vazgeçildi.")
                            client.close()
                            # Ana menüye geri dön - yeniden başlat
                            start_client(host_ip, port, show_welcome=True)
                            return

                    # Room ID'yi belirle (mevcut room_id veya current_room_id)
                    retry_room_id = join_room_id or current_room_id

                    # Tekrar deneme - room_id'yi kullan
                    client.send(
                        f"__join_with_new_username__:{retry_room_id}:{new_username}".encode(
                            "utf-8"
                        )
                    )

                elif "JOIN_ERROR" in response:
                    error_msg = response.split(":", 1)[1]
                    print(f"Giriş hatası: {error_msg}")
                    client.close()
                    if not is_pipe_mode:
                        # Ana menüye geri dön - yeniden başlat
                        start_client(host_ip, port, show_welcome=True)
                    return

                else:
                    print(f"Bilinmeyen yanıt: {response}")
                    client.close()
                    if not is_pipe_mode:
                        # Ana menüye geri dön - yeniden başlat
                        start_client(host_ip, port, show_welcome=True)
                    return

            except Exception as e:
                print(f"Sunucu hatası: {e}")
                client.close()
                if not is_pipe_mode:
                    # Ana menüye geri dön - yeniden başlat
                    start_client(host_ip, port, show_welcome=True)
                return
    else:
        # Hata durumu - oda/oda adı çakışması
        print("Bağlantı sonlandırılıyor.")
        client.close()
        if not is_pipe_mode:
            # Ana menüye geri dön - yeniden başlat
            start_client(host_ip, port, show_welcome=True)
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
    print("   /quit   - Uygulamayı kapat")
    print()

    # final_username'i username'e ata
    username = final_username

    # --- Sohbet Başlıyor ---
    setup_terminal()
    receive_thread = threading.Thread(
        target=receive_messages, args=(client,), daemon=True
    )
    receive_thread.start()

    sys.stdout.write(f"Siz: ")
    sys.stdout.flush()

    try:
        while not stop_thread:
            # Onay işlemi sırasında input'u duraklat
            if pause_input:
                import time

                time.sleep(0.01)  # Daha kısa bekleme
                continue

            # Non-blocking read ile stdin'i kontrol et
            import select

            if select.select([sys.stdin], [], [], 0.1)[0]:  # 0.1 saniye timeout
                char = sys.stdin.read(1)
            else:
                continue  # Timeout oldu, döngüyü tekrar kontrol et
            with input_lock:
                if char == "\n":  # Enter
                    if current_input == "/quit":
                        stop_thread = True
                        break

                    if current_input:
                        # Özel komutları kontrol et
                        if current_input == "/leave":
                            # /leave komutu için özel işlem
                            client.send(current_input.encode("utf-8"))
                            # Ana input döngüsünü duraklat ve onay işlemini bekle
                            pause_input = True
                        elif current_input in ["/help", "/users"]:
                            # Bu komutlar sunucudan yanıt bekler, direkt gönder
                            client.send(current_input.encode("utf-8"))
                        elif current_input.startswith("/"):
                            # Bilinmeyen komutlar
                            sys.stdout.write("\r\x1b[K" + f"Bilinmeyen komut: {current_input}. /help yazarak yardım alabilirsiniz.\n")
                        else:
                            # Normal mesaj - şifrele ve gönder (eğer şifreleme mevcut ise)
                            if ENCRYPTION_AVAILABLE and client_cipher:
                                encrypted_input = encrypt_message(current_input, client_cipher)
                                client.send(encrypted_input.encode("utf-8"))
                            else:
                                client.send(current_input.encode("utf-8"))

                            # Sadece normal mesajlar için echo yap (Discord formatı)
                            my_message = format_discord_message(username, current_input, room_data=client_message_data, check_grouping=True)
                            sys.stdout.write("\r\x1b[K" + my_message + "\n")

                    current_input = ""
                    sys.stdout.write(f"Siz: {current_input}")
                    sys.stdout.flush()

                elif char == "\x7f":  # Backspace
                    current_input = current_input[:-1]
                    sys.stdout.write("\r\x1b[K" + f"Siz: {current_input}")
                    sys.stdout.flush()
                else:
                    current_input += char
                    sys.stdout.write(char)
                    sys.stdout.flush()
    except (KeyboardInterrupt, SystemExit):
        pass

    # Ana döngüden çıkış - thread sonlandırma ve temizlik
    stop_thread = True
    restore_terminal()
    try:
        client.send("/quit".encode("utf-8"))
    except:
        pass
    client.close()

    # /leave ile çıkış yapıldıysa ana menüye döndür (recursive çağrı yerine return)
    if left_via_leave:
        clear_screen()
        print("Terminal Chat'e Hoş Geldiniz!")
        # Global değişkenleri sıfırla
        left_via_leave = False
        return "RETURN_TO_MENU"  # Ana menüye dön sinyali
    else:
        return None

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

    # Stdin kontrolü - pipe ile çalıştırılıp çalıştırılmadığını kontrol et
    if not sys.stdin.isatty():
        print("🔍 Script pipe ile çalıştırılıyor (örn: curl | python3)")
        print("📋 Bu durumda sadece host modu desteklenir.")
        print("💡 Normal kullanım için dosyayı indirip çalıştırın:")
        print("   wget -q -O client.py https://raw.githubusercontent.com/cnbcyln/terminal-chat/main/client.py")
        print("   python3 client.py --host")
        print()

        # Eğer --host parametresi verilmişse, host modunda çalıştır
        if len(sys.argv) >= 2 and sys.argv[1] == "--host":
            print("🚀 Host modunda başlatılıyor...")
        else:
            print("❌ Pipe modunda sadece --host kullanılabilir.")
            print("Kullanım: curl -s https://raw.githubusercontent.com/cnbcyln/terminal-chat/main/client.py | python3 - --host [port]")
            sys.exit(1)

    if len(sys.argv) == 2 and sys.argv[1] == "--host":
        # Sunucu olarak çalıştır (otomatik port)
        host_ip = "0.0.0.0"  # Diğerlerinin bağlanabilmesi için tüm arayüzleri dinle
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
        server_thread = threading.Thread(
            target=start_server, args=(host_ip, selected_port), daemon=True
        )
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

        # Ana menü döngüsü (otomatik port host modu)
        while True:
            result = start_client("127.0.0.1", selected_port, show_welcome=False)
            if result != "RETURN_TO_MENU":
                break  # Normal çıkış veya hata
            # Eğer "RETURN_TO_MENU" döndürürse döngü devam eder

    elif len(sys.argv) == 3 and sys.argv[1] == "--host":
        # Sunucu olarak çalıştır (belirtilen port)
        try:
            custom_port = int(sys.argv[2])
            if custom_port < 1024 or custom_port > 65535:
                print("❌ Port numarası 1024-65535 aralığında olmalıdır.")
                sys.exit(1)
        except ValueError:
            print("❌ Geçersiz port numarası. Sayısal bir değer girin.")
            sys.exit(1)

        host_ip = "0.0.0.0"
        print(f"🔧 Sunucu modu başlatılıyor (Port: {custom_port})...")

        # Yerel IP adresini al
        local_ip = get_local_ip()

        # Belirtilen portu kontrol et
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_socket.bind(("0.0.0.0", custom_port))
            test_socket.close()
            print(f"✅ Port {custom_port} müsait!")
            selected_port = custom_port
        except OSError:
            print(f"❌ Port {custom_port} kullanımda. Farklı bir port deneyin.")
            sys.exit(1)

        # Sunucuyu arka planda başlat
        server_thread = threading.Thread(
            target=start_server, args=(host_ip, selected_port), daemon=True
        )
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

        # Ana menü döngüsü (özel port host modu)
        while True:
            result = start_client("127.0.0.1", selected_port, show_welcome=False)
            if result != "RETURN_TO_MENU":
                break  # Normal çıkış veya hata
            # Eğer "RETURN_TO_MENU" döndürürse döngü devam eder

    elif len(sys.argv) == 3 and sys.argv[1] == "--connect":
        # İstemci olarak bir sunucuya bağlan
        host_ip = sys.argv[2].split(":")[0]  # IP adresini ayıkla
        port = int(sys.argv[2].split(":")[1]) if ":" in sys.argv[2] else DEFAULT_PORT
        print(f"{host_ip}:{port} adresindeki sunucuya bağlanılıyor...")

        # Ana menü döngüsü
        while True:
            result = start_client(host_ip, port)
            if result != "RETURN_TO_MENU":
                break  # Normal çıkış veya hata
            # Eğer "RETURN_TO_MENU" döndürürse döngü devam eder

    else:
        print("Hatalı kullanım.")
        print("Sunucu olarak başlatmak için:")
        print("  python3 client.py --host                    # Otomatik port (12345+)")
        print("  python3 client.py --host <PORT>             # Belirtilen port")
        print("Bir sunucuya bağlanmak için:")
        print("  python3 client.py --connect <IP_ADRESI>:<PORT>")
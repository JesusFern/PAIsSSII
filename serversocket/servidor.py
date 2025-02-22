import logging
import os
import hmac
import hashlib
import secrets
import socket
import sqlite3
import threading
import time
import tkinter as tk
from tkinter import scrolledtext
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

global SECRET_KEY
SECRET_KEY = secrets.token_bytes(32)  # Generates a secure random 32-byte key

# Configuración de directorios y rutas
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, '..', 'logs')
DB_DIR = os.path.join(BASE_DIR, '..', 'bd y claves')

DB_KEY_PATH = os.path.join(DB_DIR, "db_key.key")
LOG_PATH = os.path.join(LOG_DIR, 'server.log')
DB_PATH = os.path.join(DB_DIR, 'usuarios.db')
AUDIT_LOG_PATH = os.path.join(LOG_DIR, 'audit.log')

# Crear directorios si no existen
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)

# Funciones para obtener o generar las claves
def get_database_key():
    if os.path.exists(DB_KEY_PATH):
        with open(DB_KEY_PATH, "rb") as key_file:
            return key_file.read().strip()
    else:
        key = Fernet.generate_key()
        with open(DB_KEY_PATH, "wb") as key_file:
            key_file.write(key)
        return key

DATABASE_ENCRYPTION_KEY = get_database_key()
FERNET_CIPHER = Fernet(DATABASE_ENCRYPTION_KEY)

# Asegurar permisos de la base de datos
if os.path.exists(DB_PATH):
    os.chmod(DB_PATH, 0o600)  # Solo lectura/escritura para el usuario propietario
    
# Configuración de tiempos y límites
NONCE_EXPIRATION_TIME = 180  # Tiempo de expiración en segundos para el nonce
MAX_INTENTOS = 5 # Numero de intentos antes de bloqueo
BLOQUEO_TIEMPO = 300  # Tiempo de bloqueo en segundos (5 minutos)
INTENTOS_EXPIRATION_TIME = 300  # Tiempo de expiración para intentos fallidos (1 hora)
SESSION_TIMEOUT = 300  # Tiempo de inactividad en segundos (5 minutos)

# Estructuras de datos para gestión de sesiones y seguridad
client_nonces = {}
active_sessions = {}    

# -------------------------------
# Funciones de Diffie-Hellman
# -------------------------------
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters

def generate_dh_key(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(serialized_key, parameters):
    return serialization.load_pem_public_key(serialized_key, backend=None)

def compute_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

# -------------------------------
# Funciones de Base de Datos
# -------------------------------
def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute("PRAGMA foreign_keys = ON;")  # Asegurar integridad referencial
        conn.execute("PRAGMA journal_mode = WAL;")  # Mejor resistencia a fallos
        conn.execute("PRAGMA busy_timeout = 5000;")  # Esperar si la base de datos está bloqueada
        return conn
    except sqlite3.Error as e:
        logging.error(f"Database connection error: {e}")
        return None

def encrypt_data(data):
    if isinstance(data, str) and not data.startswith('gAAAAA'):  # Prefijo común de datos encriptados por Fernet
        return FERNET_CIPHER.encrypt(data.encode()).decode()
    return data

def decrypt_data(encrypted_data):
    if isinstance(encrypted_data, str) and encrypted_data.startswith('gAAAAA'):
        try:
            return FERNET_CIPHER.decrypt(encrypted_data.encode()).decode()
        except cryptography.fernet.InvalidToken:
            return encrypted_data
    return encrypted_data

def create_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                        username TEXT PRIMARY KEY,
                        hashed_password TEXT,
                        salt TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS transacciones (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cuenta_origen TEXT,
                        cuenta_destino TEXT,
                        cantidad TEXT,
                        hash TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS intentos_fallidos (
                        username TEXT PRIMARY KEY,
                        intentos INTEGER,
                        ultimo_intento REAL)''')
    conn.commit()
    conn.close()

def register_user(username, password):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if cursor.execute('SELECT 1 FROM usuarios WHERE username = ?', (username,)).fetchone():
            return False
        
        salt = secrets.token_hex(32)
        hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
        encrypted_password = encrypt_data(hashed_password)
        encrypted_salt = encrypt_data(salt)
        try:
            cursor.execute('INSERT INTO usuarios (username, hashed_password, salt) VALUES (?, ?, ?)',
                           (username, encrypted_password, encrypted_salt))
            conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            return False

def authenticate_user(username, password):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        current_time = time.time()

        intentos_data = cursor.execute('SELECT intentos, ultimo_intento FROM intentos_fallidos WHERE username = ?', (username,)).fetchone()
        if intentos_data and intentos_data[0] >= MAX_INTENTOS and current_time - intentos_data[1] < BLOQUEO_TIEMPO:
            return 'ACCOUNT_BLOCKED'

        stored_data = cursor.execute('SELECT hashed_password, salt FROM usuarios WHERE username = ?', (username,)).fetchone()
        if not stored_data:
            return 'LOGIN_FAILED'

        stored_password, stored_salt = stored_data
        decrypted_password = decrypt_data(stored_password)
        decrypted_salt = decrypt_data(stored_salt)

        hashed_input_password = hashlib.sha256((password + decrypted_salt).encode()).hexdigest()

        if secure_comparator(hashed_input_password, decrypted_password, SECRET_KEY):
            cursor.execute('DELETE FROM intentos_fallidos WHERE username = ?', (username,))
            active_sessions[username] = current_time
            return 'LOGIN_SUCCESSFUL'

        cursor.execute('INSERT OR REPLACE INTO intentos_fallidos (username, intentos, ultimo_intento) VALUES (?, COALESCE((SELECT intentos + 1 FROM intentos_fallidos WHERE username = ?), 1), ?)',
                       (username, username, current_time))
        return 'LOGIN_FAILED'

def record_transaction(cuenta_origen, cuenta_destino, cantidad):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Convertir la cantidad a string para hashing y encriptación
    cantidad_str = str(cantidad)

    # Generar un hash de la transacción (SHA-256)
    transaction_data = f"{cuenta_origen}:{cuenta_destino}:{cantidad_str}"
    transaction_hash = hashlib.sha256(transaction_data.encode()).hexdigest()

    # Encriptar datos sensibles
    encrypted_origen = encrypt_data(cuenta_origen)
    encrypted_destino = encrypt_data(cuenta_destino)
    encrypted_cantidad = encrypt_data(cantidad_str)
    encrypted_hash = encrypt_data(transaction_hash)

    # Verificar si la transacción ya existe con comparador seguro
    cursor.execute("SELECT cantidad, hash FROM transacciones WHERE cuenta_origen=? AND cuenta_destino=?",
                   (encrypted_origen, encrypted_destino))
    existing_transaction = cursor.fetchone()

    if existing_transaction:
        stored_amount, stored_hash = existing_transaction
        decrypted_stored_hash = decrypt_data(stored_hash)
        if secure_comparator(transaction_hash, decrypted_stored_hash, SECRET_KEY):
            conn.close()
            return False  # No registrar transacción duplicada

    # Insertar la nueva transacción
    try:
        cursor.execute('INSERT INTO transacciones (cuenta_origen, cuenta_destino, cantidad, hash) VALUES (?, ?, ?, ?)',
                       (encrypted_origen, encrypted_destino, encrypted_cantidad, encrypted_hash))
        conn.commit()
        log_audit(f"Transacción registrada: Origen={cuenta_origen}, Destino={cuenta_destino}, Cantidad={cantidad}")
        
        # Realizar verificación de integridad después de la transacción
        perform_database_integrity_check()
        
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()
        
# -------------------------------
# Funciones de Seguridad
# -------------------------------
def generate_nonce():
    return secrets.token_hex(16)

def generate_hmac(message, secret_key):
    if isinstance(secret_key, str):
        secret_key = secret_key.encode()
    return hmac.new(secret_key, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(message, received_hmac, secret_key):
    expected_hmac = generate_hmac(message, secret_key)
    return secure_comparator(expected_hmac, received_hmac, secret_key)

def verify_nonce_and_timestamp(client_address, nonce, timestamp):
    current_time = time.time()
    if abs(current_time - float(timestamp)) > NONCE_EXPIRATION_TIME:
        return False
    if nonce in client_nonces.get(client_address, {}):
        return False
    client_nonces.setdefault(client_address, {})[nonce] = current_time
    return True

def clean_old_nonces():
    while True:
        current_time = time.time()
        for client in list(client_nonces):
            client_nonces[client] = {nonce: ts for nonce, ts in client_nonces[client].items() if current_time - ts <= NONCE_EXPIRATION_TIME}
            if not client_nonces[client]:
                del client_nonces[client]
        time.sleep(5)

def secure_comparator(value1, value2, secret_key):
    if secret_key is None:
        logging.warning("SECRET_KEY is None. Using default comparison.")
        return value1 == value2

    if isinstance(secret_key, str):
        secret_key = secret_key.encode()
    
    if isinstance(value1, str):
        value1 = value1.encode()
    
    if isinstance(value2, str):
        value2 = value2.encode()
    
    mac1 = hmac.new(secret_key, value1, hashlib.sha256).digest()
    mac2 = hmac.new(secret_key, value2, hashlib.sha256).digest()
    return secrets.compare_digest(mac1, mac2)

def log_audit(message):
    with open(AUDIT_LOG_PATH, 'a') as audit_file:
        audit_file.write(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] - {message}\n')

# -------------------------------
# Funciones de Limpieza y Mantenimiento
# -------------------------------
def clean_old_failed_attempts():
    with get_db_connection() as conn:
        conn.execute('DELETE FROM intentos_fallidos WHERE ultimo_intento < ?', 
                     (time.time() - INTENTOS_EXPIRATION_TIME,))
        conn.commit()
    log_audit("Limpieza de intentos fallidos antiguos realizada.")

def perform_database_integrity_check():
    global SECRET_KEY
    if SECRET_KEY is None:
        logging.warning("SECRET_KEY is not set. Skipping database integrity check.")
        return

    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Obtener todas las transacciones
        cursor.execute("SELECT id, cuenta_origen, cuenta_destino, cantidad, hash FROM transacciones")
        transactions = cursor.fetchall()
        
        for transaction in transactions:
            id, encrypted_origen, encrypted_destino, encrypted_cantidad, encrypted_hash = transaction
            
            # Desencriptar los datos
            cuenta_origen = decrypt_data(encrypted_origen)
            cuenta_destino = decrypt_data(encrypted_destino)
            cantidad = decrypt_data(encrypted_cantidad)
            stored_hash = decrypt_data(encrypted_hash)
            
            # Recalcular el hash de la transacción
            transaction_data = f"{cuenta_origen}:{cuenta_destino}:{cantidad}"
            calculated_hash = hashlib.sha256(transaction_data.encode()).hexdigest()
            
            # Comparar los hashes de manera segura
            if not secure_comparator(calculated_hash, stored_hash, SECRET_KEY):
                log_audit(f"Integridad comprometida en la transacción ID {id}")
                return False
        
        log_audit("Verificación de integridad de la base de datos completada con éxito")
        return True
    
    except sqlite3.Error as e:
        log_audit(f"Error durante la verificación de integridad de la base de datos: {e}")
        return False
    
    finally:
        conn.close()

def backup_database():
    backup_dir = os.path.join(BASE_DIR, '..', 'backup')
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
    
    backup_filename = f'usuarios_backup_{time.strftime("%Y%m%d%H%M%S")}.db'
    backup_path = os.path.join(backup_dir, backup_filename)
    
    try:
        with get_db_connection() as conn, sqlite3.connect(backup_path) as backup_conn:
            conn.backup(backup_conn)
        log_message(f"Base de datos respaldada en {backup_path}", ("Sistema", "Backup"))
        log_audit(f"Base de datos respaldada en {backup_path}")
    except sqlite3.Error as e:
        log_message(f"Error al realizar la copia de seguridad: {e}", ("Sistema", "Backup"))
        log_audit(f"Error al realizar la copia de seguridad: {e}")
    except Exception as e:
        log_message(f"Error inesperado al realizar la copia de seguridad: {e}", ("Sistema", "Backup"))
        log_audit(f"Error inesperado al realizar la copia de seguridad: {e}")

def scheduled_backup():
    while True:
        backup_database()
        time.sleep(86400) 

def check_session_timeout():
    while True:
        current_time = time.time()
        for username, last_activity in list(active_sessions.items()):
            if current_time - last_activity > SESSION_TIMEOUT:
                del active_sessions[username]
                log_audit(f"Sesión de usuario {username} expiró por inactividad.")
                log_message(f"Sesión de usuario {username} expiró por inactividad.",("Sistema"))
        time.sleep(60)  # Verificar cada minuto

# -------------------------------
# Servidor y Gestión de Clientes
# -------------------------------
def handle_client(connection, address):
    log_message(f'Conectado con {address}', address)
    try:
        # Generar parámetros y claves DH
        parameters = generate_dh_parameters()
        private_key, public_key = generate_dh_key(parameters)
        
        # Enviar parámetros y clave pública al cliente
        serialized_params = parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        serialized_public_key = serialize_public_key(public_key)
        
        # Enviar longitud de los parámetros primero
        connection.sendall(len(serialized_params).to_bytes(4, byteorder='big'))
        connection.sendall(serialized_params)
        
        # Enviar longitud de la clave pública
        connection.sendall(len(serialized_public_key).to_bytes(4, byteorder='big'))
        connection.sendall(serialized_public_key)
        
        # Recibir clave pública del cliente
        client_public_key_length = int.from_bytes(connection.recv(4), byteorder='big')
        client_public_key_bytes = connection.recv(client_public_key_length)
        client_public_key = deserialize_public_key(client_public_key_bytes, parameters)
        
        # Calcular clave compartida
        shared_key = compute_shared_key(private_key, client_public_key)
        
        # Usar los primeros 32 bytes de la clave compartida como SECRET_KEY
        global SECRET_KEY
        SECRET_KEY = shared_key[:32]
        
        while True:
            client_nonce, timestamp = generate_nonce(), str(time.time())
            connection.sendall(f'NONCE:{client_nonce}:TIMESTAMP:{timestamp}'.encode())
            data = connection.recv(1024).decode()
            if not data:
                break
            try:
                hmac_value, message = data.split(':', 1)
                nonce, timestamp, command = message.split(':', 2)
                if verify_hmac(message, hmac_value, SECRET_KEY) and verify_nonce_and_timestamp(address, nonce, timestamp):
                    log_message(f'Mensaje Recibido:{command}', address)
                    process_client_command(connection, address, command)
                else:
                    connection.sendall(b'HMAC_FAILED or Nonce/Timestamp invalid')
            except ValueError:
                connection.sendall(b'Invalid message format')
    except Exception as e:
        log_message(f'Error en el manejo del cliente: {e}', address)
    finally:
        connection.close()
        log_message(f'Conexión cerrada con {address}', address)

def process_client_command(connection, address, message):
    parts = message.split(':')
    command = parts[0]
    response = 'Unknown command'

    if command == 'REGISTER' and len(parts) == 3:
        response = 'REGISTER_SUCCESSFUL' if register_user(parts[1], parts[2]) else 'REGISTER_FAILED'

    elif command == 'LOGIN' and len(parts) == 3:
        auth_result = authenticate_user(parts[1], parts[2])
        response = 'ACCOUNT_BLOCKED' if auth_result == 'ACCOUNT_BLOCKED' else auth_result

    elif command == 'TRANSACTION' and len(parts) == 5:
        username, origen, destino, cantidad = parts[1:]
        if username in active_sessions and username == origen:
            try:
                response = 'TRANSACTION_SUCCESSFUL' if record_transaction(origen, destino, float(cantidad)) else 'TRANSACTION_FAILED'
            except ValueError:
                response = 'TRANSACTION_FAILED'
        else:
            response = 'SESION_EXPIRE' if username not in active_sessions else 'TRANSACTION_FAILED'

    elif command == 'LOGOUT' and len(parts) == 2:
        username = parts[1]
        if username in active_sessions:
            del active_sessions[username]
            response = 'LOGOUT_SUCCESSFUL'
            log_audit(f"Usuario {username} cerró sesión.")
        else:
            response = 'SESION_EXPIRE'

    connection.sendall(response.encode())

def start_server():
    host, port = '127.0.0.1', 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(5)
        log_message(f'Servidor escuchando en {host}:{port}', (host, port))
        
        # Iniciar hilos de mantenimiento
        for task in [clean_old_nonces, clean_old_failed_attempts, 
                     check_session_timeout]:
            threading.Thread(target=task, daemon=True).start()
        
        while True:
            connection, address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(connection, address), daemon=True)
            client_thread.start()
            
            # Realizar verificación de integridad después de establecer una conexión
            threading.Thread(target=perform_database_integrity_check, daemon=True).start()

# -------------------------------
# Interfaz Gráfica (GUI)
# -------------------------------
def log_message(message, address):
    log_entry = f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] {address[0]}:{address[1]} - {message}\n\n'
    root.after(0, lambda: (text_widget.insert(tk.END, log_entry), text_widget.yview(tk.END)))
    with open(LOG_PATH, 'a') as log_file:
        log_file.write(log_entry)

# Inicialización y ejecución
if __name__ == "__main__":
    root = tk.Tk()
    root.title('Servidor de Autenticación')
    text_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
    text_widget.pack(padx=10, pady=10)

    create_db()
    
    for task in [start_server, clean_old_nonces, clean_old_failed_attempts, 
                 perform_database_integrity_check, check_session_timeout, scheduled_backup]:
        threading.Thread(target=task, daemon=True).start()

    root.mainloop()
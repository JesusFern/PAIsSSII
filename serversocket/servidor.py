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
from cryptography.fernet import Fernet

# Configuración de logging
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, '..', 'server.log')
DB_PATH = os.path.join(BASE_DIR, '..', 'usuarios.db')
AUDIT_LOG_PATH = os.path.join(BASE_DIR, '..', 'audit.log')

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)

# Clave secreta segura para HMAC
SECRET_KEY = 'super_secret_key'  # Consider using a more complex and randomly generated key
DATABASE_ENCRYPTION_KEY = Fernet.generate_key() # Clave para cifrar la base de datos
# Diccionario para almacenar nonces con timestamps
client_nonces = {}
NONCE_EXPIRATION_TIME = 300  # Tiempo de expiración en segundos
MAX_INTENTOS = 5
BLOQUEO_TIEMPO = 300  # Tiempo de bloqueo en segundos (por ejemplo, 5 minutos)
INTENTOS_EXPIRATION_TIME = 3600  # Tiempo de expiración para intentos fallidos (1 hora)
active_sessions = {}
SESSION_TIMEOUT = 10  # Tiempo de inactividad en segundos (5 minutos)

# Asegurar permisos seguros para la base de datos
if os.path.exists(DB_PATH):
    os.chmod(DB_PATH, 0o600)  # Solo lectura/escritura para el usuario propietario

# -------------------------------
# Funciones de Base de Datos
# -------------------------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON;")  # Asegurar integridad referencial
    conn.execute("PRAGMA journal_mode = WAL;")  # Mejor resistencia a fallos
    conn.execute("PRAGMA busy_timeout = 5000;")  # Esperar si la base de datos está bloqueada
    return conn

def encrypt_data(data):
    f = Fernet(DATABASE_ENCRYPTION_KEY)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    f = Fernet(DATABASE_ENCRYPTION_KEY)
    return f.decrypt(encrypted_data.encode()).decode()

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
                        cantidad REAL,
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
        cursor.execute('SELECT hashed_password, salt FROM usuarios WHERE username = ?', (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return False  # Usuario ya existe

        salt = secrets.token_hex(16)
        hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
        try:
            cursor.execute('INSERT INTO usuarios (username, hashed_password, salt) VALUES (?, ?, ?)',
                           (username, hashed_password, salt))
            conn.commit()
            return True
        except sqlite3.Error as e:
            logging.error(f"Database error: {e}")
            conn.rollback()  # Rollback in case of error
            return False

def authenticate_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Verificar intentos fallidos
    cursor.execute('SELECT intentos, ultimo_intento FROM intentos_fallidos WHERE username = ?', (username,))
    intentos_data = cursor.fetchone()
    current_time = time.time()

    if intentos_data:
        intentos, ultimo_intento = intentos_data
        if intentos >= MAX_INTENTOS and current_time - ultimo_intento < BLOQUEO_TIEMPO:
            conn.close()
            return 'ACCOUNT_BLOCKED'

    # Autenticar usuario
    cursor.execute('SELECT hashed_password, salt FROM usuarios WHERE username = ?', (username,))
    stored_data = cursor.fetchone()
    if stored_data:
        stored_password, salt = stored_data
        computed_password = hashlib.sha256((password + salt).encode()).hexdigest()

        if secure_comparator(computed_password, stored_password, SECRET_KEY):
            # Reiniciar intentos fallidos después de un inicio de sesión exitoso
            cursor.execute('DELETE FROM intentos_fallidos WHERE username = ?', (username,))
            conn.commit()
            conn.close()
            active_sessions[username] = time.time()  # Registrar la sesión activa
            return 'LOGIN_SUCCESSFUL'
        else:
            if intentos_data:
                cursor.execute('UPDATE intentos_fallidos SET intentos = intentos + 1, ultimo_intento = ? WHERE username = ?',
                               (current_time, username))
            else:
                cursor.execute('INSERT INTO intentos_fallidos (username, intentos, ultimo_intento) VALUES (?, ?, ?)',
                               (username, 1, current_time))
            conn.commit()
            conn.close()
            return 'LOGIN_FAILED'
    conn.close()
    return 'USER_NOT_FOUND'

def record_transaction(cuenta_origen, cuenta_destino, cantidad):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Verificar si el usuario autenticado es el dueño de la cuenta origen
    # Esta verificación debe realizarse antes de registrar la transacción
    # Por simplicidad, aquí asumimos que ya tienes una función para verificar esto

    # Convertir la cantidad a string para hashing
    cantidad_str = str(cantidad)

    # Generar un hash de la transacción (SHA-256)
    transaction_data = f"{cuenta_origen}:{cuenta_destino}:{cantidad_str}"
    transaction_hash = hashlib.sha256(transaction_data.encode()).hexdigest()

    # Verificar si la transacción ya existe con comparador seguro
    cursor.execute("SELECT cantidad FROM transacciones WHERE cuenta_origen=? AND cuenta_destino=?",
                   (cuenta_origen, cuenta_destino))
    existing_transaction = cursor.fetchone()

    if existing_transaction:
        stored_amount = str(existing_transaction[0])
        stored_hash = hashlib.sha256(f"{cuenta_origen}:{cuenta_destino}:{stored_amount}".encode()).hexdigest()

        # Comparación segura
        if secure_comparator(transaction_hash, stored_hash, SECRET_KEY):
            conn.close()
            return False  # No registrar transacción duplicada

    # Insertar la nueva transacción
    try:
        cursor.execute('INSERT INTO transacciones (cuenta_origen, cuenta_destino, cantidad) VALUES (?, ?, ?)',
                       (cuenta_origen, cuenta_destino, cantidad))
        conn.commit()
        log_audit(f"Transacción registrada: Origen={cuenta_origen}, Destino={cuenta_destino}, Cantidad={cantidad}")
        return True
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()
        
def check_session_timeout():
    while True:
        current_time = time.time()
        for username, last_activity in list(active_sessions.items()):
            if current_time - last_activity > SESSION_TIMEOUT:
                del active_sessions[username]
                log_audit(f"Sesión de usuario {username} expiró por inactividad.")
        time.sleep(20)  # Verificar cada minuto


# -------------------------------
# Funciones de Seguridad
# -------------------------------
def generate_nonce():
    return secrets.token_hex(16)

def generate_hmac(message, secret_key):
    return hmac.new(secret_key.encode(), message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(message, received_hmac, secret_key):
    expected_hmac = generate_hmac(message, secret_key)
    return secure_comparator(expected_hmac, received_hmac, secret_key)

def verify_nonce_and_timestamp(client_address, nonce, timestamp):
    current_time = time.time()

    # Verificar si el timestamp está dentro del tiempo permitido
    if abs(current_time - float(timestamp)) > NONCE_EXPIRATION_TIME:
        return False

    # Verificar si el nonce ya fue usado
    if client_address in client_nonces and nonce in client_nonces[client_address]:
        return False

    # Almacenar el nonce con su timestamp
    client_nonces.setdefault(client_address, {})[nonce] = current_time
    return True

def clean_old_nonces():
    """Elimina nonces que han expirado para evitar acumulación en memoria."""
    while True:
        current_time = time.time()
        for client in list(client_nonces.keys()):
            expired_nonces = [nonce for nonce, ts in client_nonces[client].items() if current_time - ts > NONCE_EXPIRATION_TIME]
            for nonce in expired_nonces:
                del client_nonces[client][nonce]

            # Si un cliente no tiene nonces activos, eliminar su entrada
            if not client_nonces[client]:
                del client_nonces[client]

        time.sleep(5)  # Ejecutar limpieza cada 5 segundos

def secure_comparator(value1, value2, secret_key):
    """
    Implementación de un comparador seguro basado en HMAC
    """
    mac1 = hmac.new(secret_key.encode(), value1.encode(), hashlib.sha256).digest()
    mac2 = hmac.new(secret_key.encode(), value2.encode(), hashlib.sha256).digest()
    return secrets.compare_digest(mac1, mac2)

def log_audit(message):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    log_entry = f'[{timestamp}] - {message}\n'
    with open(AUDIT_LOG_PATH, 'a') as audit_file:
        audit_file.write(log_entry)

# -------------------------------
# Funciones de Limpieza y Mantenimiento
# -------------------------------
def clean_old_failed_attempts():
    """Elimina registros de intentos fallidos que han expirado."""
    conn = get_db_connection()
    cursor = conn.cursor()
    current_time = time.time()
    cursor.execute('DELETE FROM intentos_fallidos WHERE ultimo_intento < ?', (current_time - INTENTOS_EXPIRATION_TIME,))
    conn.commit()
    conn.close()
    log_audit("Limpieza de intentos fallidos antiguos realizada.")

def perform_database_integrity_check():
    """Realiza una comprobación de integridad en la base de datos."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Calcula un hash de la tabla de transacciones
    cursor.execute("SELECT * FROM transacciones")
    transactions = cursor.fetchall()
    data_to_hash = str(transactions).encode('utf-8')
    calculated_hash = hashlib.sha256(data_to_hash).hexdigest()

    # Compara con el hash almacenado (si existe)
    cursor.execute("SELECT value FROM metadata WHERE key = 'transactions_hash'")
    stored_hash = cursor.fetchone()

    if stored_hash:
        if secure_comparator(calculated_hash, stored_hash[0], SECRET_KEY):
            log_message("Integridad de la base de datos verificada.", ("Sistema", "Integridad"))
        else:
            log_message("¡ALERTA! La integridad de la base de datos ha fallado.", ("Sistema", "Integridad"))
            log_audit("¡ALERTA! Fallo en la verificación de integridad de la base de datos.")
    else:
        log_message("Hash de transacciones no encontrado. Inicializando...", ("Sistema", "Integridad"))
        cursor.execute("INSERT INTO metadata (key, value) VALUES ('transactions_hash', ?)", (calculated_hash,))
        conn.commit()

    conn.close()

def backup_database():
    """Realiza una copia de seguridad de la base de datos."""
    backup_path = os.path.join(BASE_DIR, '..', 'backup', f'usuarios_backup_{time.strftime("%Y%m%d%H%M%S")}.db')
    try:
        conn = get_db_connection()
        backup_conn = sqlite3.connect(backup_path)
        with backup_conn:
            conn.backup(backup_conn)
        conn.close()
        backup_conn.close()
        log_message(f"Base de datos respaldada en {backup_path}", ("Sistema", "Backup"))
        log_audit(f"Base de datos respaldada en {backup_path}")
    except sqlite3.Error as e:
        log_message(f"Error al realizar la copia de seguridad: {e}", ("Sistema", "Backup"))
        log_audit(f"Error al realizar la copia de seguridad: {e}")

# -------------------------------
# Servidor y Gestión de Clientes
# -------------------------------
def handle_client(connection, address):
    log_message(f'Conectado con {address}', address)
    try:
        while True:
            client_nonce = generate_nonce()
            timestamp = str(time.time())
            connection.sendall(f'NONCE:{client_nonce}:TIMESTAMP:{timestamp}'.encode())
            data = connection.recv(1024).decode()
            if not data:
                break
            # log_message(f'Datos recibidos: {data}', address)
            try:
                hmac_value, message = data.split(':', 1)
                nonce, timestamp, command = message.split(':', 2)
                if verify_hmac(message, hmac_value, SECRET_KEY) and verify_nonce_and_timestamp(address, nonce, timestamp):
                    log_message(f'Mensaje Recivido:{command}', address)
                    process_client_command(connection, address, command)
                else:
                    connection.sendall(b'HMAC_FAILED or Nonce/Timestamp invalid')
            except ValueError:
                connection.sendall(b'Invalid message format')
    except (ConnectionResetError, BrokenPipeError) as e:
        log_message(f'Error de conexión: {e}', address)
    finally:
        connection.close()
        log_message(f'Conexión cerrada con {address}', address)

def process_client_command(connection, address, message):
    if message.startswith('REGISTER:'):
        _, username, password = message.split(':')
        response = 'REGISTER_SUCCESSFUL' if register_user(username, password) else 'REGISTER_FAILED'
    elif message.startswith('LOGIN:'):
        _, username, password = message.split(':')
        auth_result = authenticate_user(username, password)
        if auth_result == 'ACCOUNT_BLOCKED':
            response = 'ACCOUNT_BLOCKED'
        elif auth_result == 'LOGIN_SUCCESSFUL':
            response = 'LOGIN_SUCCESSFUL'
        else:
            response = 'LOGIN_FAILED'
    elif message.startswith('TRANSACTION:'):
        _, username, _, _, _ = message.split(':') #CONSEGUIR USUARIO
        if username and username in active_sessions:  
            parts = message.split(':')
            if len(parts) == 5:
                _, _, origen, destino, cantidad = parts
                try:
                    cantidad = float(cantidad)
                    if origen == username: # Verificar que el usuario es el dueño de la cuenta origen
                        if record_transaction(origen, destino, cantidad):
                            response = 'TRANSACTION_SUCCESSFUL'
                        else:
                            response = 'TRANSACTION_FAILED'
                    else:
                        response = 'TRANSACTION_FAILED'
                except ValueError:
                    response = 'TRANSACTION_FAILED'
            else:
                response = 'TRANSACTION_FAILED'
        else:
            response = 'SESION_EXPIRE'
    elif message.startswith('LOGOUT:'):
        _, username = message.split(':')
        if username:
            if username in active_sessions:
                del active_sessions[username]
                response = 'LOGOUT_SUCCESSFUL'
                log_audit(f"Usuario {username} cerró sesión.")
            else:
                response = 'SESION_EXPIRE' # Usuario no logueado
    else:
        response = 'Unknown command'
    connection.sendall(response.encode())

def start_server():
    host, port = '127.0.0.1', 55542
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    log_message(f'Servidor escuchando en {host}:{port}', (host, port))
    try:
        while True:
            connection, address = server_socket.accept()
            threading.Thread(target=handle_client, args=(connection, address), daemon=True).start()
    finally:
        server_socket.close()


# -------------------------------
# Interfaz Gráfica (GUI)
# -------------------------------
def log_message(message, address):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    log_entry = f'[{timestamp}] {address[0]}:{address[1]} - {message}\n\n'
    root.after(0, lambda: text_widget.insert(tk.END, log_entry))
    root.after(0, text_widget.yview, tk.END)

    # También guardar en un archivo de log
    with open('server.log', 'a') as log_file:
        log_file.write(log_entry)

root = tk.Tk()
root.title('Servidor de Autenticación')
text_widget = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
text_widget.pack(padx=10, pady=10)

create_db()
threading.Thread(target=start_server, daemon=True).start()

# Iniciar la limpieza de nonces en un hilo separado
threading.Thread(target=clean_old_nonces, daemon=True).start()

# Iniciar la limpieza de intentos fallidos antiguos
threading.Thread(target=clean_old_failed_attempts, daemon=True).start()

# Iniciar la tarea de verificación de integridad de la base de datos
threading.Thread(target=perform_database_integrity_check, daemon=True).start()

# Iniciar la tarea de respaldo de la base de datos
threading.Thread(target=backup_database, daemon=True).start()

# Iniciar la verificación de timeouts de sesión
threading.Thread(target=check_session_timeout, daemon=True).start()

root.mainloop()

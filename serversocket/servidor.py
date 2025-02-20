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

# Configuración de logging
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, '..', 'server.log')
DB_PATH = os.path.join(BASE_DIR, '..', 'usuarios.db')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)

# Clave secreta segura para HMAC
SECRET_KEY = 'super_secret_key'

# Diccionario para almacenar nonces con timestamps
client_nonces = {}
NONCE_EXPIRATION_TIME = 300  # Tiempo de expiración en segundos
MAX_INTENTOS = 5
BLOQUEO_TIEMPO = 300  # Tiempo de bloqueo en segundos (por ejemplo, 5 minutos)

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
    return conn

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
                        cantidad REAL)''')
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
        cursor.execute('INSERT INTO usuarios (username, hashed_password, salt) VALUES (?, ?, ?)',
                       (username, hashed_password, salt))
        conn.commit()
        return True

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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

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
    cursor.execute('INSERT INTO transacciones (cuenta_origen, cuenta_destino, cantidad) VALUES (?, ?, ?)',
                   (cuenta_origen, cuenta_destino, cantidad))
    conn.commit()
    conn.close()
    return True

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
        parts = message.split(':')
        if len(parts) == 4:
            _, origen, destino, cantidad = parts
            try:
                cantidad = float(cantidad)
                record_transaction(origen, destino, cantidad)
                response = 'TRANSACTION_SUCCESSFUL'
            except ValueError:
                response = 'TRANSACTION_FAILED: Invalid amount'
        else:
            response = 'TRANSACTION_FAILED: Invalid format'
    elif message == 'LOGOUT':
        response = 'LOGOUT_SUCCESSFUL'
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

root.mainloop()

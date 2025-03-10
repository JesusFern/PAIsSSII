import socket
import ssl
import concurrent.futures
import database
import logging
import os
from config import DB_PATH, MAX_INTENTOS, BLOQUEO_TIEMPO, LOG_DIR, AUDIT_LOG_PATH
import time

# Configuración del logger de auditoría
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(AUDIT_LOG_PATH)
audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
audit_logger.addHandler(audit_handler)
audit_logger.propagate = False  # Añade esta línea

# Configuración del logger principal
log_file = os.path.join(LOG_DIR, "server.log")
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(log_file), logging.StreamHandler()])

logger = logging.getLogger(__name__)

HOST = '0.0.0.0'
PORT = 8443

conn = database.get_db_connection()
database.create_db(conn)

client_users = {}

def handle_client(connstream, addr):
    username = None
    try:
        while True:
            data = connstream.recv(1024).decode()
            if not data:
                break

            logger.debug(f"Datos recibidos del cliente: {data}")

            parts = data.split(":")
            command = parts[0]

            if command == "REGISTER":
                username, password = parts[1], parts[2]
                logger.info(f"Registro - Usuario: {username}")
                if database.register_user(conn, username, password):
                    connstream.sendall(b"REGISTER_SUCCESS")
                    logger.info(f"Registro exitoso para: {username}")
                    audit_logger.info(f"Usuario registrado: {username}") #audit log
                else:
                    connstream.sendall(b"USER_EXISTS")
                    logger.warning(f"Intento de registro fallido, usuario ya existe: {username}")
                    audit_logger.warning(f"Intento de registro fallido, usuario ya existe: {username}") #audit log

            elif command == "LOGIN":
                username, password = parts[1], parts[2]
                result = database.authenticate_user(conn, username, password)
                if result == "LOGIN_SUCCESSFUL":
                    connstream.sendall(b"LOGIN_SUCCESS")
                    client_users[connstream] = username
                    logger.info(f"Inicio de sesión exitoso para: {username}")
                    audit_logger.info(f"Inicio de sesión exitoso: {username}") #audit log
                elif result == "ACCOUNT_BLOCKED":
                    connstream.sendall(b"ACCOUNT_BLOCKED")
                    logger.warning(f"Intento de inicio de sesión bloqueado para: {username}")
                    audit_logger.warning(f"Intento de inicio de sesión bloqueado: {username}") #audit log
                else:
                    connstream.sendall(b"LOGIN_FAILED")
                    logger.warning(f"Intento de inicio de sesión fallido para: {username}")
                    audit_logger.warning(f"Intento de inicio de sesión fallido: {username}") #audit log

            elif command == "MESSAGE":
                username, message = parts[1], parts[2]
                if len(message) > 144:
                    connstream.sendall(b"MESSAGE_TOO_LONG")
                    logger.warning(f"Mensaje demasiado largo de {username}")
                    audit_logger.warning(f"Mensaje demasiado largo de {username}") #audit log
                else:
                    database.save_message(conn, username, message)
                    connstream.sendall(b"MESSAGE_SENT")
                    logger.info(f"Mensaje guardado de {username}: {message}")
                    audit_logger.info(f"Mensaje guardado de {username}") #audit log

            elif command == "LOGOUT":
                username = parts[1]
                connstream.sendall(b"LOGOUT_SUCCESS")
                if connstream in client_users:
                    del client_users[connstream]
                    logger.info(f"Cierre de sesión exitoso para: {username}")
                    audit_logger.info(f"Cierre de sesión exitoso: {username}") #audit log
                username = None

    except Exception as e:
        logger.error(f"Error con cliente: {e}")
        audit_logger.error(f"Error con cliente: {e}") #audit log
    finally:
        logger.info(f"Conexión cerrada con {addr}")
        audit_logger.info(f"Conexión cerrada con {addr}") #audit log
        connstream.close()
        if connstream in client_users:
            username = client_users[connstream]
            logger.info(f"Cierre inesperado de conexión. Realizando logout para: {username}")
            audit_logger.info(f"Cierre inesperado de conexión. Realizando logout para: {username}") #audit log
            del client_users[connstream]

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")

# Cargar el certificado de la CA que firmó los certificados del cliente
context.load_verify_locations(cafile="certs/server.crt") 

# Requerir y verificar los certificados del cliente
context.verify_mode = ssl.CERT_REQUIRED

context.set_ciphers('TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384')

context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen(350)
    logger.info(f"Servidor SSL escuchando en {HOST}:{PORT}")

    try:
        with context.wrap_socket(server_socket, server_side=True) as secure_socket:
            with concurrent.futures.ThreadPoolExecutor(max_workers=400) as executor:
                while True:
                    client_socket, addr = secure_socket.accept()
                    logger.info(f"Conexión de {addr}")
                    executor.submit(handle_client, client_socket, addr)
    except ssl.SSLError as e:
        logger.error(f"Error SSL: {e}")

if conn:
    conn.close()
    logger.info("Conexión a la base de datos cerrada.")

logger.info("Servidor detenido.")
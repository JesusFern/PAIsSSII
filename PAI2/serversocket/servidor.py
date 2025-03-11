import socket
import ssl
import concurrent.futures
import logging
import database
from config import LOG_PATH, AUDIT_LOG_PATH, SSL_ENABLED, CERT_PATH, KEY_PATH, HOST, PORT, MAX_WORKERS

# Configuración del logger de auditoría
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(AUDIT_LOG_PATH)
audit_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
audit_logger.addHandler(audit_handler)
audit_logger.propagate = False

# Configuración del logger principal
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(LOG_PATH), logging.StreamHandler()])

logger = logging.getLogger(__name__)

# Inicializar la base de datos
database.create_db()

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
                if database.register_user(username, password):
                    connstream.sendall(b"REGISTER_SUCCESS")
                    logger.info(f"Registro exitoso para: {username}")
                    audit_logger.info(f"Usuario registrado: {username}")
                else:
                    connstream.sendall(b"USER_EXISTS")
                    logger.warning(f"Intento de registro fallido, usuario ya existe: {username}")
                    audit_logger.warning(f"Intento de registro fallido, usuario ya existe: {username}")

            elif command == "LOGIN":
                username, password = parts[1], parts[2]
                result = database.authenticate_user(username, password)
                if result == "LOGIN_SUCCESSFUL":
                    connstream.sendall(b"LOGIN_SUCCESS")
                    client_users[connstream] = username
                    logger.info(f"Inicio de sesión exitoso para: {username}")
                    audit_logger.info(f"Inicio de sesión exitoso: {username}")
                elif result == "ACCOUNT_BLOCKED":
                    connstream.sendall(b"ACCOUNT_BLOCKED")
                    logger.warning(f"Intento de inicio de sesión bloqueado para: {username}")
                    audit_logger.warning(f"Intento de inicio de sesión bloqueado: {username}")
                else:
                    connstream.sendall(b"LOGIN_FAILED")
                    logger.warning(f"Intento de inicio de sesión fallido para: {username}")
                    audit_logger.warning(f"Intento de inicio de sesión fallido: {username}")

            elif command == "MESSAGE":
                username, message = parts[1], parts[2]
                if len(message) > 144:
                    connstream.sendall(b"MESSAGE_TOO_LONG")
                    logger.warning(f"Mensaje demasiado largo de {username}")
                    audit_logger.warning(f"Mensaje demasiado largo de {username}")
                else:
                    database.save_message(username, message)
                    connstream.sendall(b"MESSAGE_SENT")
                    logger.info(f"Mensaje guardado de {username}: {message}")
                    audit_logger.info(f"Mensaje guardado de {username}")

            elif command == "LOGOUT":
                username = parts[1]
                connstream.sendall(b"LOGOUT_SUCCESS")
                if connstream in client_users:
                    del client_users[connstream]
                    logger.info(f"Cierre de sesión exitoso para: {username}")
                    audit_logger.info(f"Cierre de sesión exitoso: {username}")
                username = None

    except Exception as e:
        logger.error(f"Error con cliente: {e}")
        audit_logger.error(f"Error con cliente: {e}")
    finally:
        logger.info(f"Conexión cerrada con {addr}")
        audit_logger.info(f"Conexión cerrada con {addr}")
        connstream.close()
        if connstream in client_users:
            username = client_users[connstream]
            logger.info(f"Cierre inesperado de conexión. Realizando logout para: {username}")
            audit_logger.info(f"Cierre inesperado de conexión. Realizando logout para: {username}")
            del client_users[connstream]

# Configuración del contexto SSL
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=CERT_PATH, keyfile=KEY_PATH)
context.load_verify_locations(cafile=CERT_PATH)
context.verify_mode = ssl.CERT_REQUIRED
context.set_ciphers('TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-RSA-AES256-GCM-SHA384')
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen(MAX_WORKERS)
    logger.info(f"Servidor escuchando en {HOST}:{PORT}")

    try:
        if SSL_ENABLED:
            with context.wrap_socket(server_socket, server_side=True) as secure_socket:
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                    while True:
                        client_socket, addr = secure_socket.accept()
                        logger.info(f"Conexión de {addr}")
                        executor.submit(handle_client, client_socket, addr)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                while True:
                    client_socket, addr = server_socket.accept()
                    logger.info(f"Conexión de {addr}")
                    executor.submit(handle_client, client_socket, addr)
    except ssl.SSLError as e:
        logger.error(f"Error SSL: {e}")

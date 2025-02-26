import socket
import time
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Configuración del servidor
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

# Clave secreta para HMAC (se establece durante el intercambio Diffie-Hellman)
SECRET_KEY = None

# Tiempo de espera entre peticiones (en segundos)
REQUEST_DELAY = 1

# -------------------------------
# Funciones de ayuda para pruebas DAST
# -------------------------------

def generate_hmac(message, secret_key):
    """Generar un HMAC dado un mensaje y una clave secreta."""
    return hmac.new(secret_key, message.encode(), hashlib.sha256).hexdigest()

def perform_dh_exchange(sock):
    """Realizar el intercambio Diffie-Hellman con el servidor."""
    global SECRET_KEY

    # Recibir parámetros y clave pública del servidor
    params_length = int.from_bytes(sock.recv(4), byteorder='big')
    params_data = sock.recv(params_length)
    parameters = serialization.load_pem_parameters(params_data, backend=None)

    pubkey_length = int.from_bytes(sock.recv(4), byteorder='big')
    pubkey_data = sock.recv(pubkey_length)
    server_public_key = serialization.load_pem_public_key(pubkey_data, backend=None)

    # Generar nuestra clave privada y pública
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    # Enviar nuestra clave pública al servidor
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sock.sendall(len(serialized_public_key).to_bytes(4, byteorder='big'))
    sock.sendall(serialized_public_key)

    # Calcular la clave compartida
    shared_key = private_key.exchange(server_public_key)
    SECRET_KEY = shared_key[:32]

def get_nonce_and_timestamp(sock):
    """Recibir un nuevo nonce y timestamp del servidor."""
    data = sock.recv(1024).decode()
    if data.startswith("NONCE:") and "TIMESTAMP:" in data:
        parts = data.split(":")
        nonce = parts[1]
        timestamp = parts[3]
        return nonce, timestamp
    return None, None

# -------------------------------
# Pruebas DAST
# -------------------------------

def test_brute_force_login():
    """Prueba de fuerza bruta para intentar adivinar credenciales."""
    print("[*] Iniciando prueba de fuerza bruta...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    perform_dh_exchange(sock)

    for i in range(6):  # Limitar intentos para evitar bloqueos
        # Recibir un nuevo nonce y timestamp del servidor
        nonce, timestamp = get_nonce_and_timestamp(sock)
        if not nonce or not timestamp:
            print("[!] Error: No se pudo obtener nonce y timestamp del servidor.")
            break

        # Intentar adivinar credenciales
        username = f"admin"
        password = "password123"
        message = f"{nonce}:{timestamp}:LOGIN:{username}:{password}"
        hmac_value = generate_hmac(message, SECRET_KEY)
        request = f"{hmac_value}:{message}"
        sock.sendall(request.encode())

        # Recibir respuesta del servidor
        response = sock.recv(1024).decode()
        print(f"[*] Intento {i + 1}: {username}:{password} -> {response}")

        # Esperar antes de enviar la siguiente petición
        time.sleep(REQUEST_DELAY)

    sock.close()

def test_sql_injection():
    """Prueba de inyección SQL para intentar eliminar el usuario admin."""
    print("[*] Iniciando prueba de inyección SQL...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    perform_dh_exchange(sock)

    # Recibir un nuevo nonce y timestamp del servidor
    nonce, timestamp = get_nonce_and_timestamp(sock)
    if not nonce or not timestamp:
        print("[!] Error: No se pudo obtener nonce y timestamp del servidor.")
        return

    # Intentar inyección SQL para eliminar el usuario admin
    username = "test'; DELETE FROM users WHERE username = 'admin'; --"
    password = "password"
    message = f"{nonce}:{timestamp}:REGISTER:{username}:{password}"
    hmac_value = generate_hmac(message, SECRET_KEY)
    request = f"{hmac_value}:{message}"
    sock.sendall(request.encode())

    # Recibir respuesta del servidor
    response = sock.recv(1024).decode()
    print(f"[*] Respuesta del servidor: {response}")

    # Esperar antes de cerrar la conexión
    time.sleep(REQUEST_DELAY)
    sock.close()

def test_replay_attack():
    """Prueba de ataque de repetición (replay attack)."""
    print("[*] Iniciando prueba de ataque de repetición...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    perform_dh_exchange(sock)

    # Recibir un nuevo nonce y timestamp del servidor
    nonce, timestamp = get_nonce_and_timestamp(sock)
    if not nonce or not timestamp:
        print("[!] Error: No se pudo obtener nonce y timestamp del servidor.")
        return

    # Crear un mensaje válido
    username = "user1"
    password = "password1"
    message = f"{nonce}:{timestamp}:LOGIN:{username}:{password}"
    hmac_value = generate_hmac(message, SECRET_KEY)
    request = f"{hmac_value}:{message}"

    # Enviar el mensaje varias veces (simulando un ataque de repetición)
    for _ in range(6):
        sock.sendall(request.encode())
        response = sock.recv(1024).decode()
        if response.startswith("NONCE"):
            continue  # Saltar a la siguiente iteración del bucle
        
        print(f"[*] Respuesta del servidor: {response}")

        # Esperar antes de enviar la siguiente petición
        time.sleep(REQUEST_DELAY)

    sock.close()

def test_session_hijacking():
    """Prueba de secuestro de sesión (session hijacking)."""
    print("[*] Iniciando prueba de secuestro de sesión...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    perform_dh_exchange(sock)

    # Recibir un nuevo nonce y timestamp del servidor
    nonce, timestamp = get_nonce_and_timestamp(sock)
    if not nonce or not timestamp:
        print("[!] Error: No se pudo obtener nonce y timestamp del servidor.")
        return

    # Esperar para que el nonce expire
    time.sleep(15) # Hay que modificar en servidor NONCE_EXPIRATION_TIME

    # Intentar usar un nonce y timestamp antiguos
    username = "user1"
    password = "password1"
    message = f"{nonce}:{timestamp}:LOGIN:{username}:{password}"
    hmac_value = generate_hmac(message, SECRET_KEY)
    request = f"{hmac_value}:{message}"
    sock.sendall(request.encode())

    # Recibir respuesta del servidor
    response = sock.recv(1024).decode()
    print(f"[*] Respuesta del servidor: {response}")

    # Esperar antes de cerrar la conexión
    time.sleep(REQUEST_DELAY)
    sock.close()

# -------------------------------
# Ejecución de pruebas DAST
# -------------------------------

if __name__ == "__main__":
    print("[*] Iniciando pruebas DAST...")

    # Ejecutar pruebas
    test_brute_force_login()
    test_sql_injection()
    test_replay_attack()
    test_session_hijacking()

    print("[*] Pruebas DAST completadas.")
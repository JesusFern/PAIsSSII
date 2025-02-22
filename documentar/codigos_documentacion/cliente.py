import hmac
import hashlib
import socket
from interfaz_cliente import InterfazCliente
from cryptography.hazmat.primitives import serialization

# La SECRET_KEY ahora se establecerá dinámicamente
SECRET_KEY = None

def generate_hmac(message, secret_key):
    """
    Generar un HMAC dado un mensaje y una clave secreta.

    Args:
        message (str): El mensaje para el cual se generará el HMAC.
        secret_key (bytes): La clave secreta utilizada para generar el HMAC.

    Returns:
        str: El HMAC generado en formato hexadecimal.
    """
    return hmac.new(secret_key, message.encode(), hashlib.sha256).hexdigest()

def hmac_decorator(func):
    """
    Decorador para añadir HMAC a las solicitudes.

    Args:
        func (function): La función a decorar.

    Returns:
        function: La función decorada con HMAC añadido a la solicitud.
    """
    def wrapper(self, request):
        request_with_nonce_timestamp = f"{self.nonce}:{self.timestamp}:{request}"
        hmac_value = generate_hmac(request_with_nonce_timestamp, SECRET_KEY)
        request_with_hmac = f"{hmac_value}:{request_with_nonce_timestamp}"
        self.socket.sendall(request_with_hmac.encode('utf-8'))
        return func(self, request)
    return wrapper

class Cliente:
    """
    Clase Cliente que se conecta a un servidor, realiza el intercambio de claves Diffie-Hellman
    y envía/recibe solicitudes/respuestas con HMAC.

    Attributes:
        host (str): Dirección del host.
        port (int): Puerto de conexión.
        socket (socket.socket): El socket utilizado para la comunicación.
        nonce (str): El nonce utilizado en las solicitudes.
        timestamp (str): La marca de tiempo utilizada en las solicitudes.
    """
    def __init__(self, host='127.0.0.1', port=65432):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.nonce = None
        self.timestamp = None

    def connect(self):
        """Conectar al servidor y realizar el intercambio Diffie-Hellman."""
        try:
            self.socket.connect((self.host, self.port))
            import time
            time.sleep(0.5)  # Esperar medio segundo
            self.perform_dh_exchange()
            self.receive_nonce_and_timestamp()
        except socket.error as e:
            print(f"Error de conexión: {e}")

    def perform_dh_exchange(self):
        """
        Realizar el intercambio Diffie-Hellman con el servidor para establecer una clave secreta compartida.

        Raises:
            Exception: Si ocurre un error durante el intercambio Diffie-Hellman.
        """
        global SECRET_KEY

        try:
            # Recibir longitud de los parámetros
            params_length = int.from_bytes(self.socket.recv(4), byteorder='big')
            # Recibir parámetros
            params_data = self.socket.recv(params_length)
            
            # Recibir longitud de la clave pública
            pubkey_length = int.from_bytes(self.socket.recv(4), byteorder='big')
            # Recibir clave pública
            pubkey_data = self.socket.recv(pubkey_length)

            # Cargar parámetros y clave pública del servidor
            parameters = serialization.load_pem_parameters(params_data, backend=None)
            server_public_key = serialization.load_pem_public_key(pubkey_data, backend=None)

            # Generar nuestra propia clave privada y pública
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key()

            # Enviar nuestra clave pública al servidor
            serialized_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.socket.sendall(len(serialized_public_key).to_bytes(4, byteorder='big'))
            self.socket.sendall(serialized_public_key)

            # Calcular la clave compartida
            shared_key = private_key.exchange(server_public_key)

            # Usar los primeros 32 bytes de la clave compartida como SECRET_KEY
            SECRET_KEY = shared_key[:32]

        except Exception as e:
            print(f"Error durante el intercambio Diffie-Hellman: {e}")
            raise

    @hmac_decorator
    def send_request(self, request):
        """Enviar una solicitud al servidor."""
        pass

    def receive_response(self):
        """
        Recibir una respuesta del servidor.

        Returns:
            str: La respuesta recibida del servidor.
        """
        try:
            response = self.socket.recv(1024).decode('utf-8')
            return response
        except socket.error:
            return None

    def receive_nonce_and_timestamp(self):
        """Recibir un nuevo nonce y timestamp del servidor."""
        try:
            data = self.socket.recv(1024).decode('utf-8')
            if data.startswith("NONCE:") and "TIMESTAMP:" in data:
                parts = data.split(":")
                self.nonce = parts[1]
                self.timestamp = parts[3]
        except socket.error:
            pass

    def register(self, username, password):
        """
        Registrar un nuevo usuario en el servidor.

        Args:
            username (str): Nombre de usuario.
            password (str): Contraseña del usuario.

        Returns:
            str: Respuesta del servidor.
        """
        request = f"REGISTER:{username}:{password}"
        self.send_request(request)
        return self.receive_response()

    def login(self, username, password):
        """
        Iniciar sesión en el servidor.

        Args:
            username (str): Nombre de usuario.
            password (str): Contraseña del usuario.

        Returns:
            str: Respuesta del servidor.
        """
        request = f"LOGIN:{username}:{password}"
        self.send_request(request)
        return self.receive_response()

    def transaction(self, username, origen, destino, cantidad):
        """
        Realizar una transacción entre cuentas.

        Args:
            username (str): Nombre de usuario.
            origen (str): Cuenta de origen.
            destino (str): Cuenta de destino.
            cantidad (float): Cantidad a transferir.

        Returns:
            str: Respuesta del servidor.
        """
        request = f"TRANSACTION:{username}:{origen}:{destino}:{cantidad}"
        self.send_request(request)
        return self.receive_response()

    def logout(self, username):
        """
        Cerrar sesión del servidor.

        Args:
            username (str): Nombre de usuario.

        Returns:
            str: Respuesta del servidor.
        """
        request = f"LOGOUT:{username}"
        self.send_request(request)
        return self.receive_response()

    def close(self):
        """Cerrar la conexión con el servidor."""
        self.socket.close()

    def run(self):
        """Función principal para manejar la interfaz y el cliente."""
        interfaz = InterfazCliente(self)
        interfaz.run()
        self.close()

if __name__ == "__main__":
    cliente = Cliente()
    cliente.connect()
    cliente.run()
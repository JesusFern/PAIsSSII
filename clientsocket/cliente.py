import hmac
import hashlib
import socket
import tkinter as tk
from tkinter import scrolledtext, messagebox
from interfaz_cliente import InterfazCliente


# Include the secret key in the server (make sure to keep it safe)
secret_key = 'super_secret_key'

def generate_hmac(message, secret_key):
    """Generar un HMAC dado un mensaje y una clave secreta."""
    return hmac.new(secret_key.encode(), message.encode(), hashlib.sha256).hexdigest()

def hmac_decorator(func):
    """Decorador para añadir HMAC a las solicitudes."""
    def wrapper(self, request):
        request_with_nonce_timestamp = f"{self.nonce}:{self.timestamp}:{request}"
        hmac_value = generate_hmac(request_with_nonce_timestamp, secret_key)
        request_with_hmac = f"{hmac_value}:{request_with_nonce_timestamp}"
        self.socket.sendall(request_with_hmac.encode('utf-8'))
        return func(self, request)
    return wrapper

class Cliente:
    def __init__(self, host='127.0.0.1', port=55542):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.nonce = None
        self.timestamp = None

    def connect(self):
        """Conectar al servidor."""
        try:
            self.socket.connect((self.host, self.port))
            self.receive_nonce_and_timestamp()
        except socket.error:
            pass

    @hmac_decorator
    def send_request(self, request):
        """Enviar una solicitud al servidor."""
        pass

    def receive_response(self):
        """Recibir una respuesta del servidor."""
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
        """Registrar un nuevo usuario en el servidor."""
        request = f"REGISTER:{username}:{password}"
        self.send_request(request)
        return self.receive_response()

    def login(self, username, password):
        """Iniciar sesión en el servidor."""
        request = f"LOGIN:{username}:{password}"
        self.send_request(request)
        return self.receive_response()

    def transaction(self, username, origen, destino, cantidad):
        """Realizar una transacción entre cuentas."""
        request = f"TRANSACTION:{username}:{origen}:{destino}:{cantidad}"
        self.send_request(request)
        return self.receive_response()

    def logout(self, username):
        """Cerrar sesión del servidor."""
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
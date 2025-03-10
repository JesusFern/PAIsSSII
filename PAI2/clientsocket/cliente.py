import tkinter as tk
from tkinter import messagebox
import socket
import ssl
import threading
import time
from interfaz_cliente import InterfazCliente

# Configuración del cliente
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8443
TIMEOUT = 60  # Tiempo de espera en segundos

# Configurar SSL
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

class Cliente:
    def __init__(self):
        self.nonce = None
        self.timestamp = None
        self.ssock = None
        self.last_activity = time.time()
        self.connect()
        threading.Thread(target=self.check_timeout, daemon=True).start()  # Iniciar el hilo de monitoreo

    def connect(self):
        """Establecer la conexión SSL con el servidor."""
        try:
            sock = socket.create_connection((SERVER_HOST, SERVER_PORT))  # Crear el socket
            self.ssock = context.wrap_socket(sock, server_hostname=SERVER_HOST)  # Envolver con SSL
        except Exception as e:
            messagebox.showerror("Error", f"Error al conectar con el servidor: {e}")
            self.ssock = None

    def disconnect(self):
        """Cerrar la conexión SSL."""
        if self.ssock:
            try:
                self.ssock.close()
                self.ssock = None
                print("Conexión cerrada con el servidor.")
            except Exception as e:
                print(f"Error al cerrar la conexión: {e}")

    def send_data(self, command):
        """Enviar datos al servidor, solo si la conexión está establecida."""
        if self.ssock is None:
            messagebox.showerror("Error", "No hay conexión con el servidor.")
            return None

        try:
            self.ssock.sendall(command.encode())  # Enviar el comando
            response = self.ssock.recv(1024).decode()  # Esperar respuesta
            return response
        except Exception as e:
            messagebox.showerror("Error", f"Error de conexión: {e}")
            return None

    def register(self, username, password):
        """Registrar un usuario."""
        response = self.send_data(f"REGISTER:{username}:{password}")
        if response == "REGISTER_SUCCESS":
            return "REGISTER_SUCCESSFUL"
        elif response == "USER_EXISTS":
            return "REGISTER_FAILED"
        else:
            return response

    def login(self, username, password):
        """Iniciar sesión."""
        response = self.send_data(f"LOGIN:{username}:{password}")
        if response == "LOGIN_SUCCESS":
            return "LOGIN_SUCCESSFUL"
        elif response == "LOGIN_FAILED":
            return "LOGIN_FAILED"
        elif response == "ACCOUNT_BLOCKED":
            return "ACCOUNT_BLOCKED"
        else:
            return response

    def send_message(self, username, message):
        """Enviar un mensaje con validación de longitud (máximo 144 caracteres)."""
        # Verificar que el mensaje no sea mayor a 144 caracteres
        if len(message) > 144:
            messagebox.showerror("Error", "El mensaje no puede exceder los 144 caracteres.")
            return "MESSAGE_TOO_LONG"
        
        response = self.send_data(f"MESSAGE:{username}:{message}")
        if response == "MESSAGE_SENT":
            return "MESSAGE_SENT_SUCCESSFUL"
        elif response == "SESSION_EXPIRED":
            return "SESION_EXPIRE"
        else:
            return response

    def logout(self, username):
        """Cerrar sesión."""
        response = self.send_data(f"LOGOUT:{username}")
        if response == "LOGOUT_SUCCESS":
            self.disconnect() #cerrar la conexion al cerrar sesion.
            self.connect()
            return "LOGOUT_SUCCESSFUL"
        elif response == "SESSION_EXPIRED":
            return "SESION_EXPIRE"
        else:
            return response
        
    def reset_timer(self):
        self.last_activity = time.time()

    def check_timeout(self):
        while True:
            if self.ssock and time.time() - self.last_activity > TIMEOUT:
                self.disconnect()
                messagebox.showerror("Tiempo de espera", "La conexión se ha cerrado por inactividad.")
                break
            time.sleep(1)

if __name__ == "__main__":
    cliente = Cliente()
    interfaz = InterfazCliente(cliente)
    interfaz.run()
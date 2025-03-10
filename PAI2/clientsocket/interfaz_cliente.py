import tkinter as tk
from tkinter import messagebox

class InterfazCliente:
    def __init__(self, cliente):
        self.cliente = cliente
        self.logged_in = False
        self.configurar_interfaz()

    def configurar_interfaz(self):
        """Configurar la interfaz del usuario."""
        self.root = tk.Tk()
        self.root.title("Cliente de Autenticación y Mensajes")
        self.root.geometry("350x450")
        self.root.config(bg="#f0f0f0")
        self.root.resizable(False, False)

        self.crear_widgets()
        self.pack_widgets_inicial()

    def crear_widgets(self):
        """Crear los widgets de la interfaz."""
        self.title_label = tk.Label(self.root, text="Sistema de Autenticación", font=("Arial", 18, "bold"), bg="#f0f0f0")

        self.username_label = tk.Label(self.root, text="Nombre de usuario", font=("Arial", 12), bg="#f0f0f0")
        self.username_entry = tk.Entry(self.root, width=30, font=("Arial", 12))
        self.username_entry.config(validate="key", validatecommand=(self.root.register(self.validate_entry), "%P"))

        self.password_label = tk.Label(self.root, text="Contraseña", font=("Arial", 12), bg="#f0f0f0")
        self.password_entry = tk.Entry(self.root, show="*", width=30, font=("Arial", 12))
        self.password_entry.config(validate="key", validatecommand=(self.root.register(self.validate_entry), "%P"))

        self.message_label = tk.Label(self.root, text="Mensaje", font=("Arial", 12), bg="#f0f0f0")
        self.message_entry = tk.Entry(self.root, width=30, font=("Arial", 12))

        self.inform_label = tk.Message(self.root, text="", font=("Arial", 10), bg="#f0f0f0", fg="gray", width=320, justify=tk.CENTER)

        self.register_button = tk.Button(self.root, text="Registrar", width=20, font=("Arial", 12), bg="#4CAF50", fg="white", command=self.register_user)
        self.login_button = tk.Button(self.root, text="Iniciar sesión", width=20, font=("Arial", 12), bg="#2196F3", fg="white", command=self.login_user)
        self.logout_button = tk.Button(self.root, text="Cerrar sesión", width=20, font=("Arial", 12), bg="#FF5722", fg="white", command=self.logout_user)
        self.send_message_button = tk.Button(self.root, text="Enviar mensaje", width=20, font=("Arial", 12), bg="#FFC107", fg="black", command=self.send_message)

        self.footer_label = tk.Label(self.root, text="© 2025 Cliente de Autenticación", font=("Arial", 8), bg="#f0f0f0")

    def validate_entry(self, P):
        """Validar la entrada de texto, incluyendo el punto y coma."""
        if len(P) <= 20:
            if ";" in P:
                self.inform_label.config(text="No se permiten puntos y comas.")
                return False  # Rechazar la entrada
            return True
        else:
            return False

    def pack_widgets_inicial(self):
        """Organizar los widgets inicialmente."""
        self.title_label.pack(pady=10)

        self.username_label.pack(pady=5)
        self.username_entry.pack(pady=5)

        self.password_label.pack(pady=5)
        self.password_entry.pack(pady=5)

        self.inform_label.pack(pady=5)

        self.register_button.pack(pady=5)
        self.login_button.pack(pady=5)

        self.footer_label.pack(side="bottom", pady=10)

    def pack_widgets_mensaje(self):
        """Organizar los widgets de mensaje."""
        self.message_label.pack(pady=5)
        self.message_entry.pack(pady=5)

        self.inform_label.pack(pady=5)

        self.send_message_button.pack(pady=5)

    def informar_usuario(self, mensaje):
        """Actualizar el label informativo."""
        self.inform_label.config(text=mensaje)

    def register_user(self):
        """Registrar un usuario a través de la interfaz."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            response = self.cliente.register(username, password)
            if response == "REGISTER_SUCCESSFUL":
                self.informar_usuario("Usuario registrado exitosamente.")
            elif response == "REGISTER_FAILED":
                self.informar_usuario("Usuario ya registrado.")
        else:
            messagebox.showwarning("Campos vacíos", "Por favor, ingrese un nombre de usuario y una contraseña.")

    def login_user(self):
        """Iniciar sesión a través de la interfaz."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username and password:
            response = self.cliente.login(username, password)
            if response == "LOGIN_SUCCESSFUL":
                self.logged_in = True
                self.informar_usuario("Inicio de sesión exitoso.")
                self.pack_widgets_mensaje()
                self.ocultar_widgets_inicial()
                self.logout_button.pack(pady=5)
            elif response == "LOGIN_FAILED":
                self.informar_usuario("Inicio de sesión fallido.")
            elif response == "ACCOUNT_BLOCKED":
                self.informar_usuario("Cuenta bloqueada. Demasiados intentos fallidos. (Espere 5 minutos)")
        else:
            messagebox.showwarning("Campos vacíos", "Por favor, ingrese un nombre de usuario y una contraseña.")

    def ocultar_widgets_inicial(self):
        """Ocultar los widgets iniciales."""
        self.username_label.pack_forget()
        self.username_entry.pack_forget()

        self.password_label.pack_forget()
        self.password_entry.pack_forget()

        self.register_button.pack_forget()
        self.login_button.pack_forget()

    def logout_user(self):
        """Cerrar sesión a través de la interfaz."""
        if self.logged_in:
            username = self.username_entry.get()
            response = self.cliente.logout(username)
            if response == "LOGOUT_SUCCESSFUL":
                self.informar_usuario("Se ha cerrado sesión exitosamente.")
            elif response == "SESION_EXPIRE":
                self.informar_usuario("Sesion Expirada. Vuelva a iniciar sesion")
            else:
                self.informar_usuario(f"Error al cerrar sesión.\n{response}")

            self.pack_widgets_inicial()
            self.ocultar_widgets_mensaje()
            self.logout_button.pack_forget()
            self.logged_in = False

            # Limpiar los campos de entrada
            self.username_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)

        else:
            self.informar_usuario("No se puede cerrar sesión porque no has iniciado sesión.")

    def ocultar_widgets_mensaje(self):
        """Ocultar los widgets de mensaje."""
        self.message_label.pack_forget()
        self.message_entry.pack_forget()

        self.send_message_button.pack_forget()

    def send_message(self):
        """Enviar un mensaje."""
        if self.logged_in:
            username = self.username_entry.get()
            message = self.message_entry.get()
            if message:
                response = self.cliente.send_message(username, message)
                if response == "MESSAGE_SENT_SUCCESSFUL":
                    self.informar_usuario("Mensaje enviado con éxito.")
                elif response == "SESION_EXPIRE":
                    self.informar_usuario("Sesion Expirada. Vuelva a iniciar sesion")
                else:
                    self.informar_usuario(f"Error: {response}")
            else:
                messagebox.showwarning("Campo vacío", "Por favor, ingrese un mensaje.")
        else:
            self.informar_usuario("Debe iniciar sesión para enviar un mensaje.")

    def run(self):
        """Ejecutar la interfaz de usuario."""
        self.root.mainloop()
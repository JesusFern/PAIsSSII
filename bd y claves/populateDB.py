import hashlib
import sqlite3
import os
import secrets  # Para generar el salt aleatorio

# Diccionario de usuarios y contraseñas
users = {
    "admin": "admin",
    "user1": "password1",
    "user2": "password2",
    "user3": "password3",
    # Añadir más usuarios si es necesario
}

# Función para crear la base de datos y la tabla de usuarios si no existen
def create_db():
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS usuarios (
            username TEXT PRIMARY KEY,
            hashed_password TEXT,
            salt TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transacciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cuenta_origen TEXT,
            cuenta_destino TEXT,
            cantidad REAL
        )
    ''')
    conn.commit()
    conn.close()

# Función para registrar un usuario en la base de datos
def register_user(username, hashed_password, salt):
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()

    # Insertar el usuario si no existe
    cursor.execute(''' 
        INSERT OR IGNORE INTO usuarios (username, hashed_password, salt)
        VALUES (?, ?, ?)
    ''', (username, hashed_password, salt))
    conn.commit()
    conn.close()

# Función principal para popular la base de datos con usuarios de ejemplo
def main():
    # Verificar y crear la base de datos si no existe
    if not os.path.exists('usuarios.db'):
        create_db()

    # Registrar cada usuario del diccionario en la base de datos
    for user, password in users.items():
        # Generar salt aleatorio
        salt = secrets.token_hex(16)  # Genera 16 bytes de salt aleatorio
        # Concatenar salt con la contraseña antes de hashearla
        hashed_password = hashlib.sha256((password + salt).encode('utf-8')).hexdigest()
        # Registrar usuario en la base de datos
        register_user(user, hashed_password, salt)

    print("Base de datos poblada correctamente.")

if __name__ == "__main__":
    main()
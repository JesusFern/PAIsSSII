import sqlite3
import bcrypt
import time
from queue import Queue
from config import DB_PATH, MAX_INTENTOS, BLOQUEO_TIEMPO

class SQLiteConnectionPool:
    def __init__(self, database, max_connections=10):
        self.database = database
        self.max_connections = max_connections
        self.connections = Queue(maxsize=max_connections)
        self.fill_pool()

    def fill_pool(self):
        for _ in range(self.max_connections):
            conn = sqlite3.connect(self.database, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 10000;")
            self.connections.put(conn)

    def get_connection(self):
        return self.connections.get()

    def return_connection(self, connection):
        self.connections.put(connection)

    def close_all(self):
        while not self.connections.empty():
            conn = self.connections.get()
            conn.close()

# Crear el pool de conexiones
pool = SQLiteConnectionPool(DB_PATH)

def get_db_connection():
    return pool.get_connection()

def create_db():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                            username TEXT PRIMARY KEY,
                            hashed_password TEXT,
                            message_count INTEGER DEFAULT 0)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS intentos_fallidos (
                            username TEXT PRIMARY KEY,
                            intentos INTEGER,
                            ultimo_intento REAL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            sender TEXT,
                            message TEXT,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
        
        cursor.execute("SELECT COUNT(*) FROM usuarios")
        if cursor.fetchone()[0] == 0:
            users = {
                "admin": "admin",
                "user1": "password1",
                "user2": "password2",
                "user3": "password3"
            }
            for username, password in users.items():
                hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                cursor.execute('INSERT INTO usuarios (username, hashed_password, message_count) VALUES (?, ?, ?)',
                               (username, hashed_password, 0))
        conn.commit()
    except Exception as e:
        print(f"Error creating database: {e}")
    finally:
        pool.return_connection(conn)

def register_user(username, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if cursor.execute('SELECT 1 FROM usuarios WHERE username = ?', (username,)).fetchone():
            return False
        
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cursor.execute('INSERT INTO usuarios (username, hashed_password) VALUES (?, ?)',
                       (username, hashed_password))
        conn.commit()
        return True
    except Exception:
        return False
    finally:
        pool.return_connection(conn)

def authenticate_user(username, password):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        current_time = time.time()

        intentos_data = cursor.execute('SELECT intentos, ultimo_intento FROM intentos_fallidos WHERE username = ?', (username,)).fetchone()
        if intentos_data:
            if intentos_data[0] >= MAX_INTENTOS and current_time - intentos_data[1] < BLOQUEO_TIEMPO:
                return 'ACCOUNT_BLOCKED'
            elif current_time - intentos_data[1] >= BLOQUEO_TIEMPO and intentos_data[0] >= MAX_INTENTOS:
                cursor.execute('DELETE FROM intentos_fallidos WHERE username = ?', (username,))
                conn.commit()

        stored_password = cursor.execute('SELECT hashed_password FROM usuarios WHERE username = ?', (username,)).fetchone()
        
        if not stored_password:
            return 'LOGIN_FAILED'

        if bcrypt.checkpw(password.encode(), stored_password[0].encode()):
            cursor.execute('DELETE FROM intentos_fallidos WHERE username = ?', (username,))
            conn.commit()
            return 'LOGIN_SUCCESSFUL'

        cursor.execute('INSERT OR REPLACE INTO intentos_fallidos (username, intentos, ultimo_intento) VALUES (?, COALESCE((SELECT intentos + 1 FROM intentos_fallidos WHERE username = ?), 1), ?)',
                       (username, username, current_time))
        conn.commit()
        return 'LOGIN_FAILED'
    finally:
        pool.return_connection(conn)

def save_message(sender, message):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Insertar el mensaje en la tabla 'messages'
        cursor.execute("INSERT INTO messages (sender, message) VALUES (?, ?)", (sender, message))
        
        # Actualizar el contador de mensajes en la tabla 'usuarios'
        cursor.execute("UPDATE usuarios SET message_count = message_count + 1 WHERE username = ?", (sender,))
        
        conn.commit()
    finally:
        pool.return_connection(conn)
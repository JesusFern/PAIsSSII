import os
import secrets
from cryptography.fernet import Fernet

# Clave secreta global
SECRET_KEY = secrets.token_bytes(32)  # Genera una clave aleatoria segura de 32 bytes

# Configuración de directorios y rutas
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Modified line
LOG_DIR = os.path.join(BASE_DIR, 'logs')  # Corrected to be in same dir
DB_DIR = os.path.join(BASE_DIR, 'bd_claves') # Corrected to be in same dir

DB_KEY_PATH = os.path.join(DB_DIR, "db_key.key")
LOG_PATH = os.path.join(LOG_DIR, 'server.log')
DB_PATH = os.path.join(DB_DIR, 'usuarios.db')
AUDIT_LOG_PATH = os.path.join(LOG_DIR, 'audit.log')

# Crear el directorio de logs si no existe
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
    os.chmod(LOG_DIR, 0o700) #Permisos solo para el dueño

if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

# Configuración de logging (si tienes logging aquí, mantenlo)

# Funciones para obtener o generar las claves
def get_database_key():
    if os.path.exists(DB_KEY_PATH):
        with open(DB_KEY_PATH, "rb") as key_file:
            return key_file.read().strip()
    else:
        key = Fernet.generate_key()
        with open(DB_KEY_PATH, "wb") as key_file:
            key_file.write(key)
        return key

DATABASE_ENCRYPTION_KEY = get_database_key()
FERNET_CIPHER = Fernet(DATABASE_ENCRYPTION_KEY)

# Asegurar permisos de la base de datos
if os.path.exists(DB_PATH):
    os.chmod(DB_PATH, 0o600)  # Solo lectura/escritura para el usuario propietario

# Configuración de seguridad para intentos de inicio de sesión
MAX_INTENTOS = 3
BLOQUEO_TIEMPO = 60 * 5  # 5 minutos
HOST = '0.0.0.0'
PORT = 8443
SESSION_TIMEOUT = 60  # Tiempo de inactividad en segundos
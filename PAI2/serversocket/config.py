import os

# Configuración de directorios y rutas
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, 'logs')
DB_DIR = os.path.join(BASE_DIR, 'bd_claves')

DB_KEY_PATH = os.path.join(DB_DIR, "db_key.key")
LOG_PATH = os.path.join(LOG_DIR, 'server.log')
DB_PATH = os.path.join(DB_DIR, 'usuarios.db')
AUDIT_LOG_PATH = os.path.join(LOG_DIR, 'audit.log')

# Crear el directorio de logs si no existe
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
    os.chmod(LOG_DIR, 0o700)

if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

# Asegurar permisos de la base de datos
if os.path.exists(DB_PATH):
    os.chmod(DB_PATH, 0o600)

# Configuración de seguridad para intentos de inicio de sesión
MAX_INTENTOS = 3
BLOQUEO_TIEMPO = 60 * 5  # 5 minutos

# Configuración del servidor
HOST = '0.0.0.0'
PORT = 8443
MAX_WORKERS = 350

# Configuración SSL
SSL_ENABLED = True
CERT_PATH = "certs/server.crt"
KEY_PATH = "certs/server.key"
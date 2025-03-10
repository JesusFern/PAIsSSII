import socket
import time
import threading
import ssl

# Configuración del cliente
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8443
NUM_USUARIOS = 300  # Reducir el número para evitar problemas de recursos

# Configurar SSL
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

def cliente_simulado(usuario_id, failed):
    """Simula un cliente que se conecta al servidor SSL."""
    try:
        sock = socket.create_connection((SERVER_HOST, SERVER_PORT))
        ssock = context.wrap_socket(sock, server_hostname=SERVER_HOST)

        # Simular registro
        username = f"admin"
        password = "admin"

        # Simular inicio de sesión
        message = f"LOGIN:{username}:{password}"
        ssock.sendall(message.encode())
        response = ssock.recv(1024).decode()
        # print(f"[*] Usuario {usuario_id}: {username}:{password} -> {response}")
        
        # Verificar que la respuesta sea "LOGIN_SUCCESS"
        if response != "LOGIN_SUCCESS":
            print(f"[*] Error en usuario {usuario_id}: Login fallido. Respuesta: {response}")
            failed += 1

        ssock.close()
    except ConnectionRefusedError:
        print(f"[*] Error en usuario {usuario_id}: Conexión rechazada. Verifica que el servidor esté en ejecución.")
    except Exception as e:
        print(f"[*] Error en usuario {usuario_id}: {e}")

def prueba_carga_simultanea():
    """Crea y ejecuta múltiples clientes concurrentes."""
    print(f"[*] Iniciando prueba de carga con {NUM_USUARIOS} usuarios...")
    start_time = time.time()  # Captura el tiempo de inicio

    threads = []
    failed = 0  # Contador de fallos
    for i in range(NUM_USUARIOS):
        thread = threading.Thread(target=cliente_simulado, args=(i, failed))
        threads.append(thread)
        thread.start()

    # Esperar a que todos los hilos terminen
    for thread in threads:
        thread.join()

    end_time = time.time()  # Captura el tiempo de finalización
    elapsed_time = end_time - start_time

    print("[*] Prueba de carga completada.")
    print(f"[*] Tiempo total de prueba: {elapsed_time:.2f} segundos.")
    print(f"[*] Fallos: {failed} usuarios.")

if __name__ == "__main__":
    prueba_carga_simultanea()
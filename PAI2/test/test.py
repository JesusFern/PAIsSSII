import socket
import time
import threading
import ssl

# Configuración del cliente
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 8443
NUM_USUARIOS = 300  
USE_SSL = False  # Cambia esto a False si no quieres usar SSL

# Configurar SSL
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="../certs/client.crt", keyfile="../certs/client.key")
context.check_hostname = False  # Eliminar en producción
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(cafile="../certs/server.crt")

def cliente_simulado(usuario_id, fallos):
    """Simula un cliente que se conecta al servidor, con o sin SSL."""
    try:
        sock = socket.create_connection((SERVER_HOST, SERVER_PORT))
        
        if USE_SSL:
            ssock = context.wrap_socket(sock, server_hostname=SERVER_HOST)
        else:
            ssock = sock

        # Simular registro
        username = f"admin"
        password = "admin"

        # Simular inicio de sesión
        message = f"LOGIN:{username}:{password}"
        ssock.sendall(message.encode())
        response = ssock.recv(1024).decode()
        
        # Verificar que la respuesta sea "LOGIN_SUCCESS"
        if response != "LOGIN_SUCCESS":
            print(f"[*] Error en usuario {usuario_id}: Login fallido. Respuesta: {response}")
            fallos[0] += 1  # Incrementar el contador de fallos

        ssock.close()
    except ConnectionRefusedError:
        print(f"[*] Error en usuario {usuario_id}: Conexión rechazada. Verifica que el servidor esté en ejecución.")
    except Exception as e:
        print(f"[*] Error en usuario {usuario_id}: {e}")
        fallos[0] += 1  # Incrementar el contador de fallos

def calculo_rendimientos():
    tiempos = []
    for _ in range(100):
        start_time = time.perf_counter()
        fallos = [0]  # Contador de fallos como una lista para pasarlo por referencia
        hilo = threading.Thread(target=cliente_simulado, args=(0, fallos))
        hilo.start()
        hilo.join()
        elapsed_time = time.perf_counter() - start_time
        tiempos.append(elapsed_time)
        print(f"Tiempo: {elapsed_time:.6f}s | Fallos: {fallos[0]}")

    promedio = sum(tiempos) / len(tiempos)
    print(f"Promedio: {promedio:.6f}s")

def prueba_carga_simultanea():
    """Crea y ejecuta múltiples clientes concurrentes."""
    print(f"[*] Iniciando prueba de carga con {NUM_USUARIOS} usuarios...")
    start_time = time.perf_counter()  # Captura el tiempo de inicio

    threads = []
    fallos = [0]  # Contador de fallos como una lista para pasarlo por referencia
    for i in range(NUM_USUARIOS):
        thread = threading.Thread(target=cliente_simulado, args=(i, fallos))
        threads.append(thread)
        thread.start()

    # Esperar a que todos los hilos terminen
    for thread in threads:
        thread.join()

    elapsed_time = time.perf_counter() - start_time  # Captura el tiempo de finalización

    print("[*] Prueba de carga completada.")
    print(f"[*] Tiempo total de prueba: {elapsed_time:.6f} segundos.")
    print(f"[*] Fallos: {fallos[0]} usuarios.")

if __name__ == "__main__":
    calculo_rendimientos()
    time.sleep(5)
    if USE_SSL:
        prueba_carga_simultanea()
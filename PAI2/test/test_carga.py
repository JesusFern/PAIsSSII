import socket
import time
import threading
import ssl
import psutil
import platform

# --- Configuración del Test de Carga ---
SERVER_HOST = '127.0.0.1'  # Dirección IP del servidor
SERVER_PORT = 8443        # Puerto del servidor
NUM_USUARIOS = 300       # Número de usuarios concurrentes
USE_SSL = True            # Usar SSL/TLS (True/False)

# --- Configuración SSL/TLS ---
if USE_SSL:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_cert_chain(certfile="../certs/client.crt", keyfile="../certs/client.key")
    context.check_hostname = False  # Desactivar en producción
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="../certs/server.crt")

def mostrar_caracteristicas_dispositivo():
    """Muestra las características del dispositivo."""
    print("--- Características del Dispositivo ---")
    print(f"Sistema Operativo: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Procesador: {platform.processor()}")
    print(f"Número de CPUs Físicas: {psutil.cpu_count(logical=False)}")
    print(f"Número de CPUs Lógicas: {psutil.cpu_count(logical=True)}")
    print(f"Memoria RAM Total: {psutil.virtual_memory().total / (1024 ** 3):.2f} GB")
    print("---------------------------------------")

def cliente_simulado(usuario_id, fallos, tiempos):
    """Simula un cliente que se conecta y realiza un inicio de sesión."""
    start_time = time.perf_counter()
    try:
        sock = socket.create_connection((SERVER_HOST, SERVER_PORT))
        ssock = context.wrap_socket(sock, server_hostname=SERVER_HOST) if USE_SSL else sock

        message = "LOGIN:admin:admin"
        ssock.sendall(message.encode())
        response = ssock.recv(1024).decode()

        if response != "LOGIN_SUCCESS":
            print(f"[*] Error: Usuario {usuario_id} - Login fallido.")
            print(f"    Mensaje enviado: {message}")
            print(f"    Respuesta recibida: {response}")
            fallos[0] += 1

        ssock.close()
    except ConnectionRefusedError:
        print(f"[*] Error: Usuario {usuario_id} - Conexión rechazada.")
        fallos[0] += 1
    except Exception as e:
        print(f"[*] Error: Usuario {usuario_id} - {e}")
        fallos[0] += 1
    finally:
        elapsed_time = time.perf_counter() - start_time
        tiempos.append(elapsed_time)

def prueba_carga_simultanea():
    """Realiza una prueba de carga simultánea."""
    print(f"\n--- Prueba de Carga Simultánea ({NUM_USUARIOS} usuarios) ---")
    start_time = time.perf_counter()

    threads = []
    fallos = [0]
    tiempos = []
    for i in range(NUM_USUARIOS):
        thread = threading.Thread(target=cliente_simulado, args=(i, fallos, tiempos))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    elapsed_time = time.perf_counter() - start_time
    print(f"\nTiempo total: {elapsed_time:.6f}s")
    print(f"Fallos totales: {fallos[0]}")

def monitorizar_recursos():
    """Monitoriza el uso de CPU y RAM."""
    print("\n--- Monitorización de Recursos ---")
    while True:
        cpu_percent = psutil.cpu_percent(interval=1)
        ram_percent = psutil.virtual_memory().percent
        print(f"CPU: {cpu_percent}% | RAM: {ram_percent}%")
        time.sleep(1)

if __name__ == "__main__":
    mostrar_caracteristicas_dispositivo()
    if USE_SSL:
        monitor_thread = threading.Thread(target=monitorizar_recursos)
        monitor_thread.daemon = True
        monitor_thread.start()
        prueba_carga_simultanea()
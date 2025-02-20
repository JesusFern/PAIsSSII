import subprocess
import sys

def run_server():
    """Ejecutar el servidor en segundo plano sin abrir consola visible."""
    if sys.platform == "win32":
        # En Windows, usamos pythonw.exe para evitar que se abra la consola
        subprocess.Popen(['pythonw', 'serversocket/servidor.py'], 
                         creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        print(f"Este script está diseñado para Windows. No se puede ejecutar en {sys.platform}.")
    
    print("Servidor ejecutándose en segundo plano sin consola visible.")

def run_client():
    """Ejecutar el cliente sin mostrar la consola."""
    if sys.platform == "win32":
        # En Windows, usamos pythonw.exe para evitar que se abra la consola
        subprocess.Popen(['pythonw', 'clientsocket/cliente.py'], 
                         creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        print(f"Este script está diseñado para Windows. No se puede ejecutar en {sys.platform}.")
    
    print("Cliente ejecutándose en segundo plano sin consola visible.")

if __name__ == "__main__":
    # Ejecutar el servidor en segundo plano
    run_server()

    # Ejecutar el cliente en segundo plano
    run_client()
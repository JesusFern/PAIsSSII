import subprocess
import sys

def run_server():
    """Ejecutar el servidor en segundo plano sin abrir consola visible."""
    if sys.platform == "win32":
        # En Windows, usamos pythonw.exe para evitar que se abra la consola
        
        subprocess.Popen(['python', 'serversocket/salt_server.py'], 
                         creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.Popen(['python', 'serversocket/servidor.py'], 
                         creationflags=subprocess.CREATE_NO_WINDOW)
    else:
        print(f"Este script está diseñado para Windows. No se puede ejecutar en {sys.platform}.")
    
    print("Servidor ejecutándose en segundo plano sin consola visible.")

def run_client():
    """Ejecutar el cliente mostrando la consola."""
    if sys.platform == "win32":
        # En Windows, usamos 'cmd /c start' para abrir una nueva ventana de consola
        subprocess.Popen('cmd /c start cmd /k python clientsocket/cliente.py', shell=True)
    else:
        print(f"Este script está diseñado para Windows. No se puede ejecutar en {sys.platform}.")
    
    print("Cliente ejecutándose en una nueva ventana de consola.")

if __name__ == "__main__":
    # Ejecutar el servidor en segundo plano
    run_server()

    # Ejecutar el cliente en una nueva ventana de consola
    run_client()

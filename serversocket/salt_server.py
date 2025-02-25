import socket
import threading
import secrets

# Diccionario para almacenar las sales
salts = {}

def handle_client(connection, address):
    try:
        while True:
            data = connection.recv(1024).decode()
            if not data:
                break
            command, username = data.split(':')
            if command == 'GET_SALT':
                salt = salts.get(username, secrets.token_hex(32))
                salts[username] = salt
                connection.sendall(salt.encode())
            elif command == 'SET_SALT':
                salt = secrets.token_hex(32)
                salts[username] = salt
                connection.sendall(salt.encode())
    except Exception as e:
        print(f"Error handling client {address}: {e}")
    finally:
        connection.close()

def start_salt_server():
    host, port = '127.0.0.1', 65433
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f'Salt server listening on {host}:{port}')
        while True:
            connection, address = server_socket.accept()
            threading.Thread(target=handle_client, args=(connection, address), daemon=True).start()

if __name__ == "__main__":
    start_salt_server()
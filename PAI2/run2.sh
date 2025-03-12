#!/bin/bash

# Abrir un terminal para ejecutar el servidor
gnome-terminal -- bash -c "echo 'Ejecutando servidor'; python3 serversocket/servidor.py; exec bash"

# Esperar 5 segundos antes de ejecutar el cliente
sleep 2

# Abrir otro terminal para ejecutar el cliente
gnome-terminal -- bash -c "echo 'Ejecutando cliente'; python3 clientsocket/cliente.py; exec bash"

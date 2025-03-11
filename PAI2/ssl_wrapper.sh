#!/bin/bash

# Colores para mejorar la presentación
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuración
SERVIDOR="127.0.0.1:8443"
CERT="certs/client.crt"
KEY="certs/client.key"

# Ejecutar openssl s_client y filtrar la salida
SALIDA=$(echo "Q" | openssl s_client -connect "$SERVIDOR" -cert "$CERT" -key "$KEY" 2>/dev/null)

# Información del Certificado
echo -e "\n${BLUE}▓▓▓ Información del Certificado ▓▓▓${NC}"
echo -e "${YELLOW}Sujeto:${NC}"
echo "$SALIDA" | grep "subject=" | sed 's/subject=//' | sed 's/,/\n/g' | sed 's/^/  /'
echo -e "\n${YELLOW}Emisor:${NC}"
echo "$SALIDA" | grep "issuer=" | sed 's/issuer=//' | sed 's/,/\n/g' | sed 's/^/  /'

# Protocolo y Cifrado
echo -e "\n${BLUE}▓▓▓ Protocolo y Cifrado ▓▓▓${NC}"
echo "$SALIDA" | grep -E "Protocol:|Cipher" | sort | uniq | sed 's/^[[:space:]]*//'

# Verificación del Certificado
echo -e "\n${BLUE}▓▓▓ Verificación del Certificado ▓▓▓${NC}"
verify=$(echo "$SALIDA" | grep "verify error")
if [ -z "$verify" ]; then
    echo -e "${GREEN}No se encontraron errores de verificación${NC}"
else
    echo -e "${RED}$verify${NC}"
fi

# 📝 Dunder Tifflin

Dunder Tifflin es un sistema de gestión para una empresa de venta de mateial de oficina que permite manejar clientes, inventarios, ventas y reportes de manera eficiente. Inspirado en la icónica compañía ficticia de *The Office*, este proyecto busca implementar un sistema sencillo y funcional para pequeñas empresas.

---

## 📋 Características

- **Gestión de clientes**: Registro, consulta, actualización y eliminación de datos de clientes.
- **Control de inventario**: Seguimiento de productos, cantidades disponibles y actualizaciones de stock.
- **Módulo de ventas**: Registro de transacciones y generación de reportes.
- **Reportes personalizados**: Análisis de ventas y estado del inventario.
- **Interfaz amigable**: Pensada para ser sencilla e intuitiva.

---

## 📂 Estructura del proyecto

```
Dunder-Tifflin/
├── src/              # Código fuente principal
├── data/             # Datos de prueba e inventario
├── tests/            # Pruebas unitarias
├── README.md         # Documentación del proyecto
├── requirements.txt  # Dependencias del proyecto
```

---

## 🚀 Instalación y uso

1. **Clonar el repositorio**  
   ```bash
   git clone https://github.com/Pablito2442/Dunder-Tifflin.git
   cd Dunder-Tifflin
   ```

2. **Crear un entorno virtual** (opcional pero recomendado)  
   ```bash
   python -m venv env
   source env/bin/activate  # En Windows usa env\Scripts\activate
   ```

3. **Instalar dependencias**
   Para Linux
   ```bash
   pip install -r requirements.txt && ./generarDB.sh
   ```
   Para Windows
   ```bash
   pip install -r requirements.txt && ./GenerarDB.bat
   ```

5. **Ejecutar el sistema**  
   ```bash
   python manage.py runserver
   ```

---

## 🛠️ Tecnologías utilizadas

- **Lenguaje:** Python 3.8+
- **Bibliotecas principales:**
  - Django: Estruturacion del proyecto .

---

## 📈 Futuras mejoras

- **Autenticación y roles de usuario.**
- **Módulo de facturación integrado.**
- **Exportación de reportes a formatos como PDF y Excel.**
- **Diseño responsivo para dispositivos móviles.**
- **Integración con APIs de envío y logística.**

---

## 🖼️ Créditos

Inspirado por *The Office*, una serie que nos recuerda la importancia del humor incluso en las oficinas más peculiares. 🎉  

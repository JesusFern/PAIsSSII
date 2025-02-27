import os
import subprocess
import sys

def run_command(command):
    print(f"Ejecutando comando: {command}")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    output, error = process.communicate()
    if error:
        print(f"Error: {error}")
    if process.returncode != 0:
        print(f"El comando falló con código de salida {process.returncode}")
        sys.exit(1)
    return output

def modify_conf_py(conf_path):
    print("Modificando conf.py...")
    with open(conf_path, "r+") as f:
        content = f.read()
        f.seek(0, 0)
        new_content = """import os
import sys
sys.path.insert(0, os.path.abspath('../codigos_documentacion'))

# -- Theme configuration -----------------------------------------------------
import sphinx_rtd_theme

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx_rtd_theme',
]

html_theme = 'sphinx_rtd_theme'

html_static_path = ['_static']

# Agregar archivo CSS personalizado
def setup(app):
    app.add_css_file('custom.css')

"""
        f.write(new_content + content)

def main():
    # Verificar la estructura del proyecto
    print(f"Directorio actual: {os.getcwd()}")
    if not os.path.exists("codigos_documentacion"):
        print("Error: No se encuentra la carpeta 'codigos_documentacion'")
        sys.exit(1)

    # Instalar Sphinx y el tema Read the Docs
    print("Instalando Sphinx y el tema Read the Docs...")
    run_command("pip install sphinx sphinx_rtd_theme")

    # Crear directorio de documentación
    print("Creando directorio de documentación...")
    os.makedirs("docs", exist_ok=True)
    os.chdir("docs")
    print(f"Cambiado al directorio: {os.getcwd()}")

    # Ejecutar sphinx-quickstart
    print("Configurando Sphinx...")
    run_command('sphinx-quickstart --no-sep -p "Your Project" -a "Author" -v 1.0 -r 1.0 -l en --ext-autodoc --ext-viewcode')

    # Encontrar conf.py
    conf_path = "conf.py"
    if os.path.exists("source/conf.py"):
        conf_path = "source/conf.py"
    print(f"Usando conf.py en: {conf_path}")

    # Modificar conf.py
    modify_conf_py(conf_path)

    # Crear directorio _static para CSS personalizado
    os.makedirs("_static", exist_ok=True)
    with open("_static/custom.css", "w") as f:
        f.write("""/* Tu CSS personalizado aquí */
        body {
            background-color: #f0f0f0;
        }""")

    # Generar archivos de documentación
    print("Generando archivos de documentación...")
    run_command("sphinx-apidoc -o . ../codigos_documentacion")

    # Encontrar index.rst
    index_path = "index.rst"
    if os.path.exists("source/index.rst"):
        index_path = "source/index.rst"
    print(f"Usando index.rst en: {index_path}")

    # Modificar index.rst
    print("Modificando index.rst...")
    with open(index_path, "r+") as f:
        content = f.read()
        f.seek(0, 0)
        f.write("""
Welcome to Your Project's documentation!
========================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   modules

""" + content)

    # Generar documentación HTML
    print("Generando documentación HTML...")
    run_command("sphinx-build -b html . _build")

    # Verificar si se generó la documentación
    if os.path.exists("_build/index.html"):
        print("Documentación generada con éxito. Abra docs/_build/index.html en su navegador para verla.")
    else:
        print("Error: No se encontró el archivo index.html en _build/")

if __name__ == "__main__":
    main()
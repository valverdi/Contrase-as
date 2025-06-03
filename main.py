import os
import json
import base64
import getpass
import bcrypt
import secrets
import string
import hashlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ======= CONFIG =======
USERS_FILE = "usuarios.sec"
DATA_DIR = "data"
ADMIN_SALT = b"pepper_del_sistema"

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# ======= FUNCIONES CRIPTO =======

def derivar_clave(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def obtener_fernet(password: str, salt: bytes) -> Fernet:
    key = derivar_clave(password, salt)
    return Fernet(key)

def generar_id_usuario(username: str) -> str:
    h = hashlib.sha256()
    h.update((username + "pepper_interna").encode())
    return h.hexdigest()[:12]

# ======= ADMIN: cargar y guardar usuarios =======

def cargar_usuarios(admin_pwd: str) -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "rb") as f:
        datos_cifrados = f.read()
    fernet = obtener_fernet(admin_pwd, ADMIN_SALT)
    try:
        datos_json = fernet.decrypt(datos_cifrados)
        return json.loads(datos_json)
    except:
        print("❌ Clave de administrador incorrecta.")
        return None

def guardar_usuarios(admin_pwd: str, usuarios: dict):
    fernet = obtener_fernet(admin_pwd, ADMIN_SALT)
    datos_json = json.dumps(usuarios).encode()
    datos_cifrados = fernet.encrypt(datos_json)
    with open(USERS_FILE, "wb") as f:
        f.write(datos_cifrados)

# ======= REGISTRO Y LOGIN =======

def registrar_usuario(usuarios: dict, admin_pwd: str) -> tuple:
    username = input("Nuevo nombre de usuario: ").strip()
    if username in usuarios:
        print("⚠️ Ese usuario ya existe.")
        return None

    pwd = getpass.getpass("Contraseña maestra del usuario: ")
    hash_pwd = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

    usuarios[username] = {
        "hash": hash_pwd
    }
    guardar_usuarios(admin_pwd, usuarios)

    user_id = generar_id_usuario(username)
    # Guardamos salt para derivar clave usuario
    with open(os.path.join(DATA_DIR, f"{user_id}.salt"), "wb") as f:
        f.write(os.urandom(16))

    print("✅ Usuario registrado correctamente.")
    return username, pwd

def login_usuario(usuarios: dict) -> tuple:
    username = input("Usuario: ").strip()
    if username not in usuarios:
        print("❌ Usuario no encontrado.")
        return None

    pwd = getpass.getpass("Contraseña maestra: ")
    if not bcrypt.checkpw(pwd.encode(), usuarios[username]["hash"].encode()):
        print("❌ Contraseña incorrecta.")
        return None

    return username, pwd

# ======= GESTIÓN DE DATOS CIFRADOS =======

def cargar_datos(user_id: str, fernet: Fernet) -> dict:
    path = os.path.join(DATA_DIR, f"{user_id}.enc")
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        datos_cifrados = f.read()
    try:
        return json.loads(fernet.decrypt(datos_cifrados))
    except Exception as e:
        print("❌ Error al descifrar los datos:", e)
        return {}

def guardar_datos(user_id: str, fernet: Fernet, datos: dict):
    path = os.path.join(DATA_DIR, f"{user_id}.enc")
    datos_json = json.dumps(datos).encode()
    with open(path, "wb") as f:
        f.write(fernet.encrypt(datos_json))

# ======= GESTIÓN DE COPIA ADMIN =======

def guardar_copia_admin(user_id: str, datos: dict, fernet_admin: Fernet):
    path = os.path.join(DATA_DIR, f"{user_id}_admin.enc")
    datos_json = json.dumps(datos).encode()
    with open(path, "wb") as f:
        f.write(fernet_admin.encrypt(datos_json))

def cargar_copia_admin(user_id: str, fernet_admin: Fernet) -> dict:
    path = os.path.join(DATA_DIR, f"{user_id}_admin.enc")
    if not os.path.exists(path):
        return {}
    with open(path, "rb") as f:
        datos_cifrados = f.read()
    try:
        return json.loads(fernet_admin.decrypt(datos_cifrados))
    except Exception as e:
        print("❌ Error al descifrar copia admin:", e)
        return {}

# ======= FUNCIONES AUXILIARES =======

def generar_password(longitud=12):
    caracteres = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(caracteres) for _ in range(longitud))

def medir_fortaleza(password):
    puntos = 0
    if len(password) >= 8: puntos += 1
    if any(c.islower() for c in password): puntos += 1
    if any(c.isupper() for c in password): puntos += 1
    if any(c.isdigit() for c in password): puntos += 1
    if any(c in string.punctuation for c in password): puntos += 1
    niveles = ["Muy débil", "Débil", "Media", "Buena", "Fuerte"]
    return niveles[min(puntos, len(niveles)-1)]

def menu_usuario():
    print("\n--- Menú Usuario ---")
    print("1. Ver registros")
    print("2. Agregar registro")
    print("3. Editar registro")
    print("4. Eliminar registro")
    print("5. Salir")

def menu_admin():
    print("\n--- Menú Admin ---")
    print("1. Listar usuarios")
    print("2. Ver registros de un usuario")
    print("3. Salir")

# ======= MAIN =======

if __name__ == "__main__":


    if usuarios is None:
        exit()

    print("\n1. Registrarse")
    print("2. Iniciar sesión")
    opcion = input("Seleccione una opción: ")

    if opcion == "1":
        resultado = registrar_usuario(usuarios, admin_pwd)
    elif opcion == "2":
        resultado = login_usuario(usuarios)
    else:
        print("❌ Opción inválida.")
        exit()

    if resultado is None:
        exit()

    username, user_pwd = resultado
    user_id = generar_id_usuario(username)

    # Leer salt para derivar clave usuario
    salt_path = os.path.join(DATA_DIR, f"{user_id}.salt")
    if not os.path.exists(salt_path):
        print("❌ Salt del usuario no encontrado.")
        exit()
    with open(salt_path, "rb") as f:
        salt = f.read()

    # Claves Fernet para usuario y admin
    fernet_user = obtener_fernet(user_pwd, salt)
    fernet_admin = obtener_fernet(admin_pwd, ADMIN_SALT)

    datos = cargar_datos(user_id, fernet_user)

    # Si el usuario es admin (por ejemplo, usuario "admin"), abrimos menú admin
    if username == "admin":
        while True:
            menu_admin()
            op = input("Opción: ")
            if op == "1":
                print("Usuarios registrados:")
                for u in usuarios.keys():
                    print(f"- {u}")
            elif op == "2":
                user_sel = input("Ingrese nombre de usuario a consultar: ")
                if user_sel not in usuarios:
                    print("Usuario no encontrado.")
                    continue
                user_sel_id = generar_id_usuario(user_sel)
                datos_admin = cargar_copia_admin(user_sel_id, fernet_admin)
                if not datos_admin:
                    print("No hay registros o no existe copia admin para este usuario.")
                    continue
                print(f"Registros de {user_sel}:")
                for nombre, pwd in datos_admin.items():
                    print(f"{nombre}: {pwd}")
            elif op == "3":
                print("👋 Hasta luego.")
                break
            else:
                print("Opción inválida.")
    else:
        # Menú usuario normal
        while True:
            menu_usuario()
            op = input("Opción: ")

            if op == "1":
                if not datos:
                    print("No hay registros.")
                else:
                    for nombre, pwd in datos.items():
                        print(f"{nombre}: {pwd}")

            elif op == "2":
                nombre = input("Nombre del registro: ")
                usar_gen = input("¿Generar contraseña aleatoria? (s/n): ").lower()
                if usar_gen == "s":
                    pwd = generar_password()
                    print(f"Contraseña generada: {pwd}")
                else:
                    pwd = input("Contraseña: ")
                print("Fortaleza:", medir_fortaleza(pwd))
                datos[nombre] = pwd

                # Guardar datos cifrados usuario
                guardar_datos(user_id, fernet_user, datos)
                # Guardar copia cifrada admin
                guardar_copia_admin(user_id, datos, fernet_admin)
                print("Registro guardado.")

            elif op == "3":
                nombre = input("Nombre del registro a editar: ")
                if nombre not in datos:
                    print("Registro no encontrado.")
                    continue
                pwd = input("Nueva contraseña: ")
                print("Fortaleza:", medir_fortaleza(pwd))
                datos[nombre] = pwd
                guardar_datos(user_id, fernet_user, datos)
                guardar_copia_admin(user_id, datos, fernet_admin)
                print("Registro actualizado.")

            elif op == "4":
                nombre = input("Nombre del registro a eliminar: ")
                if nombre not in datos:
                    print("Registro no encontrado.")
                    continue
                del datos[nombre]
                guardar_datos(user_id, fernet_user, datos)
                guardar_copia_admin(user_id, datos, fernet_admin)
                print("Registro eliminado.")

            elif op == "5":
                print("👋 Hasta luego.")
                break
            else:
                print("Opción inválida.")

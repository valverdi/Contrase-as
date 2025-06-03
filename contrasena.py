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

# ===================== CONFIGURACIÓN =====================

USERS_FILE = "usuarios.sec"
DATA_DIR = "data"
ADMIN_SALT = b'pepper_del_sistema'  # fija pero secreta

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# ===================== UTILIDADES CRIPTO =====================

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
    return h.hexdigest()[:12]  # ID anónimo corto

# ===================== ADMIN: ACCESO A USUARIOS =====================

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

# ===================== REGISTRO Y LOGIN DE USUARIOS =====================

def registrar_usuario(usuarios: dict) -> tuple:
    username = input("Nuevo nombre de usuario: ").strip()
    if username in usuarios:
        print("⚠️ Ese usuario ya existe.")
        return None

    pwd = getpass.getpass("Contraseña maestra del usuario: ")
    hash_pwd = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

    usuarios[username] = hash_pwd
    guardar_usuarios(admin_pwd, usuarios)

    user_id = generar_id_usuario(username)

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
    if not bcrypt.checkpw(pwd.encode(), usuarios[username].encode()):
        print("❌ Contraseña incorrecta.")
        return None

    return username, pwd

# ===================== GESTIÓN DE REGISTROS CIFRADOS =====================

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

# ===================== FUNCIONES EXTRA =====================

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
def menu():
    print("\n--- Gestor de Contraseñas ---")
    print("1. Ver registros")
    print("2. Agregar registro")
    print("3. Editar registro")
    print("4. Eliminar registro")
    print("5. Salir")

# ===================== MAIN =====================

if __name__ == "__main__":
    print("🔐 Ingrese clave del ADMIN para continuar:")
    admin_pwd = getpass.getpass("Clave admin: ")
    usuarios = cargar_usuarios(admin_pwd)

    if usuarios is None:
        exit()

    print("\n1. Registrarse")
    print("2. Iniciar sesión")
    opcion = input("Seleccione una opción: ")

    if opcion == "1":
        resultado = registrar_usuario(usuarios)
    elif opcion == "2":
        resultado = login_usuario(usuarios)
    else:
        print("❌ Opción inválida.")
        exit()

    if resultado is None:
        exit()

    username, user_pwd = resultado
    user_id = generar_id_usuario(username)

    with open(os.path.join(DATA_DIR, f"{user_id}.salt"), "rb") as f:
        salt = f.read()

    fernet = obtener_fernet(user_pwd, salt)
    datos = cargar_datos(user_id, fernet)

    while True:
        menu()
        op = input("Opción: ")

        if op == "1":
            if not datos:
                print("No hay registros.")
            for nombre, pwd in datos.items():
                print(f"{nombre}: {pwd}")

        elif op == "2":
            nombre = input("Nombre del registro: ")
            usar_gen = input("¿Generar contraseña aleatoria? (s/n): ").lower()
            if usar_gen == "s":
                pwd = generar_password()
                print(f"Contraseña generada: {pwd}")
            else:
                pwd = getpass.getpass("Ingrese contraseña: ")
            print("Fortaleza:", medir_fortaleza(pwd))
            datos[nombre] = pwd
            guardar_datos(user_id, fernet, datos)

        elif op == "3":
            nombre = input("Registro a editar: ")
            if nombre in datos:
                pwd = getpass.getpass("Nueva contraseña: ")
                print("Fortaleza:", medir_fortaleza(pwd))
                datos[nombre] = pwd
                guardar_datos(user_id, fernet, datos)
            else:
                print("No existe ese registro.")

        elif op == "4":
            nombre = input("Registro a eliminar: ")
            if nombre in datos:
                del datos[nombre]
                guardar_datos(user_id, fernet, datos)
                print("Registro eliminado.")
            else:
                print("No existe ese registro.")

        elif op == "5":
            print("👋 Hasta luego.")
            break

        else:
            print("❌ Opción inválida.")

import os
import json
import base64
import hashlib

from cryptography.fernet import Fernet


class PasswordManager:
	def __init__(self,config):
		self.fernet = None
		self.config = config
		self.user_dict = {}
		
		self.load_users()

	def get_hash(self, data):
		return hashlib.sha512(data).hexdigest()
	
	def get_salt(self, size):
		return os.urandom(size)
	
	def derive_key(self, password, salt, n = 2**14, r = 8, p = 1, dklen = 32):
		"""
		Utiliza un key derivation function, para obtener una clave a
		partir del master password del usuario.
		
		Al resultado obtenido se le hace un encode en base64 para que se pueda 
		utilizar al momento de encriptar datos con fernet.
		"""
		
		key = hashlib.scrypt(
			password,
			salt = salt,
			n = n,
			r = r,
			p = p,
			dklen = dklen,
		)

		return base64.urlsafe_b64encode(key)

	def encrypt_data(self, data):
		return self.fernet.encrypt(data.encode())

	def decrypt_data(self, data):
		return self.fernet.decrypt(data).decode()

	def load_users(self):
		"""
		Se encarga de leer el archivo que contiene informacion de los usuarios registrados.
		
		Los datos almacenados en el archivo tienen el siguiente formato:
		
		dict { id: [hash,salt], id: [hash,salt], ... }
		
		- id unico para cada usuario ( se obtiene haciendo un hash al nombre del usuario )
		- hash ( se obtiene haciendo un hash de la clave derivada del master password + salt )
		- salt ( un valor random unico para cada usuario, almacenado con un encode en base64 )
		"""
		
		user_file = self.config['Files']['users']

		with open(user_file,"rt") as f:
			data = f.read()
			data = data.strip()
			
			if data != "":
				self.user_dict = json.loads(data)

	def create_user(self, username, password):
		"""
		Se encarga de crear los datos necesarios del nuevo usuario:
		- En el diccionario de usuarios.
		- En en el archivo de usuarios.
		- El archivo de credenciales.
		"""
		
		user_id = self.get_hash(username.encode())
		user_salt = self.get_salt(32)
		user_hash = self.derive_key(password.encode(),user_salt)
		user_hash = self.get_hash(user_hash)
		
		self.user_dict[user_id] = [user_hash, base64.b64encode(user_salt).decode()]
		
		user_file = self.config['Files']['users']
		
		with open(user_file,"wt") as f:
			f.write(json.dumps(self.user_dict))
		
		self.create_credentials(username)

	def delete_user(self, username):
		"""
		Se encarga de eliminar los datos correspondientes al usuario:
		- Del diccionario de usuarios.
		- Del archivo de usuarios.
		- El archivo de credenciales.
		"""
		
		user_id = self.get_hash(username.encode())
		user_file = self.config['Files']['users']
		
		del self.user_dict[user_id]
		
		with open(user_file,"wt") as f:
			if not self.user_dict:
				pass
			else:
				f.write(json.dumps(self.user_dict))
		
		credentials_file = user_id
		credentials_path = os.path.join(self.config['Paths']['credentials'],credentials_file)
		os.remove(credentials_path)

	def verify_user(self, username):
		"""
		Verifica si el usuario esta registrado o no.
		
		Retorna:
		- True si el usuario existe.
		- False si el usuario no existe.
		"""

		user_id = self.get_hash(username.encode())
		
		if self.user_dict.get(user_id) == None:
			return False
		
		return True

	def verify_login(self, username, password):
		"""
		Verifica que las credenciales de login del usuario sean validas.
		
		Adicionalmente si las credenciales son validas, genera la clave 
		utilizada por fenet para encriptar y desencriptar los datos.
		
		Retorna:
		- True si las credenciales son validas.
		- False si las credenciales no son validas.
		"""

		if not self.verify_user(username):
			return False
		
		user_id = self.get_hash(username.encode())
		user_hash = self.user_dict[user_id][0]
		user_salt = self.user_dict[user_id][1]
		user_salt = base64.b64decode(user_salt)

		key = self.derive_key(password.encode(),user_salt)
		key_hash = self.get_hash(key)
		
		if user_hash != key_hash:
			return False

		self.fernet = Fernet(key)
		return True

	def load_credentials(self, username):
		"""
		Lee el archivo de credenciales del usuario, y desencripta el contenido.
		
		Retorna un dict con las credenciales del usuario { id: { site: "", username: "", password: "" } }.
		"""

		credentials_file = self.get_hash(username.encode())		
		credentials_path = os.path.join(self.config['Paths']['credentials'],credentials_file)
		
		decrypted_credentials = {}
		
		with open(credentials_path,"rb") as f:
			encrypted_credentials = f.read()
			
			if encrypted_credentials != b'':
				decrypted_credentials = json.loads(self.decrypt_data(encrypted_credentials))
		
		return decrypted_credentials

	def insert_credentials(self, username, credentials):
		"""
		Encripta y almacena las credenciales correspondientes al usuario.
		
		Se sobreescribe el archivo de credenciales previo con las nuevas credenciales.
		"""
		
		credentials_file = self.get_hash(username.encode())
		credentials_path = os.path.join(self.config['Paths']['credentials'],credentials_file)
		
		with open(credentials_path,"wb") as f:
			if not credentials:
				pass
			else:
				encrypted_credentials = self.encrypt_data(json.dumps(credentials))
				f.write(encrypted_credentials)

	def create_credentials(self, username):
		"""
		Crea el archivo de credenciales correspondiente al usuario.
		"""
		
		credentials_file = self.get_hash(username.encode())
		credentials_path = os.path.join(self.config['Paths']['credentials'],credentials_file)
		
		with open(credentials_path,"wb"):
			pass


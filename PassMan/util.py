import os
import base64
import getpass
import configparser

from passman import *
from configparser import *
from zxcvbn import zxcvbn

class Util:
	def __init__(self, config_path):
		self.load_config(config_path)
		self.create_directories()
		self.create_files()
		
		self.current_user = None
		self.pm = PasswordManager(self.config)

	def load_config(self, path):
		self.config = configparser.ConfigParser(interpolation=ExtendedInterpolation())
		self.config.read(path)

	def set_current_menu(self, menu):
		self.current_menu = menu

	def is_password_strong(self, password):
		result = zxcvbn(password)

		if result['score'] == 4:
			return True

		return False

	def get_strong_password(self, length = 12):
		password = base64.b64encode(os.urandom(length)).decode()
		
		while not self.is_password_strong(password):
			password = base64.b64encode(os.urandom(length)).decode()
		
		return password
	
	def get_user_password(self):
		gen_pass = input("Generar contraseña ? [s/N]: ")
		
		if gen_pass.lower() == "s":
			password = self.get_strong_password()
			print("Contraseña generada:",password)
		else:		
			password = getpass.getpass("Contraseña: ")
			
			while not self.is_password_strong(password):
				print(
				"\nLa contraseña ingresada es debil.\n"
				"\nUna contraseña fuerte consiste de:\n"
				"- Una longitud mayor o igual a 12.\n"
				"- Uno o mas numeros.\n"
				"- Uno o mas caracteres en minuscula.\n"
				"- Uno o mas caracteres en mayuscula.\n"
				"- Uno o mas caracteres especiales. ( ej: !<=>*()+,- )\n"
				)
				
				password = getpass.getpass("\nContraseña: ")
		
		return password

	def create_directories(self):
		for _ in self.config['Paths']:
			d = self.config['Paths'][_]
			
			if not os.path.exists(d):
				os.makedirs(d)
			
			if d == "home":
				os.chdir(d)

	def create_files(self):
		for _ in self.config['Files']:
			f = self.config['Files'][_]
			
			if not os.path.exists(f):
				with open(f,"w"):
					pass

	def create_user(self):
		username = input("\nUsuario: ")
		
		if self.pm.verify_user(username):
			print("\nEl usuario ya existe.")
			return
		
		password = self.get_user_password()

		if username == password:
			print("\nEl usuario y la contraseña no pueden ser iguales.")
			return
			
		self.pm.create_user(username,password)
		print("\nUsuario registrado.")

	def delete_user(self):
		username = input("\nUsuario: ")
		password = getpass.getpass("Contraseña: ")
		
		if self.pm.verify_login(username,password):
			self.pm.delete_user(username)
			print("\nUsuario eliminado.")
		else:
			print("\nError, credenciales invalidas.")

	def view_credentials(self):
		credentials = self.pm.load_credentials(self.current_user['username'])
		
		if credentials:
			for i,(k,v) in enumerate(credentials.items(),1):
				print(f'\n{i})\nUsuario: {k}\nContraseña: {v}')
		else:
			print("\nNo hay credenciales almacenadas.")

	def insert_credentials(self):
		print("\nIngrese los datos de su credencial:\n")
		
		username = input("Usuario: ")
		password = self.get_user_password()
		
		if username == password:
			print("\nEl usuario y la contraseña no pueden ser iguales.")
			return
		
		credentials = self.pm.load_credentials(self.current_user['username'])
		credentials[username] = password
		self.pm.insert_credentials(self.current_user['username'], credentials)
		print("\nCredenciales almacenadas.")

	def delete_credentials(self):
		temp = {}
		credentials = self.pm.load_credentials(self.current_user['username'])
		credentials_len = len(credentials)
		
		if credentials:
			for i,(k,v) in enumerate(credentials.items(),1):
				print(f'\n{i})\nUsuario: {k}\nContraseña: {v}\n')
				temp[i] = k
			
			while True:
				print("\nIngrese el numero de la credencial que desea eliminar [ 0 para cancelar ].")
				
				try:
					option = int(input("\nOpcion: "))
					
					if option == 0:
						break
					
					if option >= 1 and option <= credentials_len:
						del credentials[temp[option]]
						self.pm.insert_credentials(self.current_user['username'],credentials)
						print("\nCredenciales eliminadas.")
						break
				except ValueError:
					pass
				
				print("\nOpcion invalida.")
		else:
			print("\nNo hay credenciales almacenadas.")

	def modify_credentials(self):
		temp = {}
		credentials = self.pm.load_credentials(self.current_user['username'])
		credentials_len = len(credentials)
		
		if credentials:
			for i,(k,v) in enumerate(credentials.items(),1):
				print(f'\n{i})\nUsuario: {k}\nContraseña: {v}\n')
				temp[i] = k
			
			while True:
				print("\nIngrese el numero de la credencial que desea modificar [ 0 para cancelar ].")
				
				try:
					option = int(input("\nOpcion: "))
					
					if option == 0:
						break
					
					if option >= 1 and option <= credentials_len:
						print("\nIngrese los nuevos datos de su credencial:\n")
						
						username = input("Usuario: ")
						password = self.get_user_password()
						
						if username == password:
							print("\nEl usuario y la contraseña no pueden ser iguales.")
							return
						
						del credentials[temp[option]]
						credentials[username] = password
						self.pm.insert_credentials(self.current_user['username'],credentials)
						print("\nCredenciales modificadas.")
						break
				except ValueError:
					pass
				
				print("\nOpcion invalida.")
		else:
			print("\nNo hay credenciales almacenadas.")

	def login(self):
		username = input("\nUsuario: ")
		password = getpass.getpass("Contraseña: ")

		if self.pm.verify_login(username,password):
			self.current_user = {
				"username": username,
				"password": password,
			}
			
			print("\nSesion iniciada.")
			return True
		else:
			print("\nUsuario o contraseña invalidos.")
			self.current_user = None
			return False

	def logout(self):
		self.pm.fernet = None
		self.current_user = None
		print("\nSesion finalizada.")

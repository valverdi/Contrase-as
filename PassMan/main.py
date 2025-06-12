from util import *

def menu_a():
	while True:
		print(
		"\n"
		"1 - Iniciar sesion.\n"
		"2 - Registrar usuario.\n"
		"3 - Eliminar usuario.\n"
		"0 - Salir.\n"
		)

		try:
			option = int(input("Opcion: "))
			
			if option >= 0 and option <= 3:
				return option
		except ValueError:
			pass
		
		print("\nOpcion invalida.")

def menu_b():
	while True:
		print(
		"\n"
		"4 - Finalizar sesion.\n"
		"5 - Agregar credenciales.\n"
		"6 - Obtener credenciales.\n"
		"7 - Eliminar credenciales.\n"
		"8 - Modificar credenciales.\n"
		)
		
		try:
			option = int(input("Opcion: "))
			
			if option >= 4 and option <= 8:
				return option
		except ValueError:
			pass
		
		print("\nOpcion invalida.")


def main():
	util = Util("config.ini")
	
	util.set_current_menu(menu_a)

	while True:
		option = util.current_menu()
		
		if option == 1:
			if util.login():
				util.set_current_menu(menu_b)
		elif option == 2:
			util.create_user()
		elif option == 3:
			util.delete_user()
		elif option == 4:
			util.logout()
			util.set_current_menu(menu_a)
		elif option == 5:
			util.insert_credentials()
		elif option == 6:
			util.view_credentials()
		elif option == 7:
			util.delete_credentials()
		elif option == 8:
			util.modify_credentials()
		elif option == 0:
			break
		else:
			print("\nError.")
			exit(1)


main()

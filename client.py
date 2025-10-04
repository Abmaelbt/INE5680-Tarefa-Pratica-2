import os
import getpass
import json
import base64
import crypto_utils
import server

# pasta para armazenar o salt do cliente
CLIENT_DATA_DIR = "client_data"

def ensure_client_dir():
    if not os.path.exists(CLIENT_DATA_DIR):
        os.makedirs(CLIENT_DATA_DIR)

def get_client_salt_path(username):
    return os.path.join(CLIENT_DATA_DIR, f"{username}_salt.json")

def save_client_salt(username, salt):
    path = get_client_salt_path(username)
    data = {"pbkdf2_salt_b64": base64.b64encode(salt).decode('utf-8')}
    with open(path, 'w') as f:
        json.dump(data, f)

def load_client_salt(username):
    path = get_client_salt_path(username)
    if not os.path.exists(path):
        return None
    with open(path, 'r') as f:
        data = json.load(f)
        return base64.b64decode(data["pbkdf2_salt_b64"])

def handle_register():
    # fluxo de registro de um novo usuario
    username = input("escolha um nome de usuario: ")
    password = getpass.getpass("escolha uma senha: ")
    
    if os.path.exists(get_client_salt_path(username)):
        print("erro: usuario ja registrado neste cliente.")
        return

    # o cliente gera e armazena seu proprio salt para derivar o token de autenticacao e a chave de cifra
    client_salt = crypto_utils.generate_salt()
    pbkdf2_token = crypto_utils.derive_pbkdf2_token(password, client_salt)
    
    totp_secret, message = server.register_user(username, pbkdf2_token)
    
    if totp_secret:
        print(f"sucesso: {message}")
        save_client_salt(username, client_salt)
        uri = crypto_utils.get_totp_uri(username, totp_secret)
        crypto_utils.display_qr_code(uri)
        print("\nimportante: escaneie o qr code com google authenticator ou similar.")
    else:
        print(f"falha no registro: {message}")

def handle_login():
    # fluxo de login e autenticacao de dois fatores
    username = input("usuario: ")
    password = getpass.getpass("senha: ")

    client_salt = load_client_salt(username)
    if not client_salt:
        print("falha na autenticacao: usuario nao encontrado neste cliente.")
        return

    # etapa 1: autenticacao com senha
    pbkdf2_token = crypto_utils.derive_pbkdf2_token(password, client_salt)
    if not server.authenticate_step1(username, pbkdf2_token):
        print("falha na autenticacao: usuario ou senha invalidos.")
        return

    # etapa 2: autenticacao com totp
    totp_code = input("codigo de autenticacao (6 digitos): ")
    if not server.authenticate_step2(username, totp_code):
        print("falha na autenticacao: codigo invalido.")
        return

    print("\nlogin bem-sucedido!")
    logged_in_menu(username, password, client_salt)

def logged_in_menu(username, password, client_salt):
    # menu de acoes para um usuario autenticado
    while True:
        print("\n--- menu principal ---")
        print("1. enviar arquivo")
        print("2. baixar arquivo")
        print("3. logout")
        choice = input("> ")

        if choice == '1':
            handle_upload(username, password, client_salt)
        elif choice == '2':
            handle_download(username, password, client_salt)
        elif choice == '3':
            print("logout realizado.")
            break
        else:
            print("opcao invalida.")

def handle_upload(username, password, client_salt):
    filepath = input("caminho do arquivo para enviar: ")
    if not os.path.exists(filepath):
        print("erro: arquivo nao encontrado.")
        return

    filename = os.path.basename(filepath)
    with open(filepath, 'rb') as f:
        file_data = f.read()

    # deriva a chave de cifra a partir da senha e do salt do cliente
    encryption_key = crypto_utils.derive_pbkdf2_token(password, client_salt)
    encrypted_content = crypto_utils.encrypt_aes_gcm(file_data, encryption_key)
    
    server.store_file(username, filename, encrypted_content)
    print(f"arquivo '{filename}' enviado com sucesso.")

def handle_download(username, password, client_salt):
    filename = input("nome do arquivo para baixar: ")
    
    encrypted_content = server.retrieve_file(username, filename)
    if not encrypted_content:
        print("erro: arquivo nao encontrado no servidor.")
        return

    # deriva a mesma chave de cifra para decifrar o arquivo
    decryption_key = crypto_utils.derive_pbkdf2_token(password, client_salt)
    decrypted_data = crypto_utils.decrypt_aes_gcm(encrypted_content, decryption_key)

    if decrypted_data:
        print("\n--- conteudo do arquivo decifrado ---")
        try:
            # tenta decodificar como texto, se falhar, mostra os bytes
            print(decrypted_data.decode('utf-8'))
        except UnicodeDecodeError:
            print(f"(dados binarios): {decrypted_data}")
        print("------------------------------------")
    else:
        print("falha ao decifrar o arquivo. a senha pode estar incorreta ou o arquivo corrompido.")

def main():
    ensure_client_dir()
    while True:
        print("\n--- servico de nuvem segura ---")
        print("1. registrar")
        print("2. login")
        print("3. sair")
        choice = input("> ")

        if choice == '1':
            handle_register()
        elif choice == '2':
            handle_login()
        elif choice == '3':
            break
        else:
            print("opcao invalida.")

if __name__ == "__main__":
    main()

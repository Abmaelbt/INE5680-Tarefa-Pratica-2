import os
import getpass
import json
import base64
import requests
import crypto_utils
import logging

# configuracao de logs para o cliente
logging.basicConfig(level=logging.INFO, format='[CLIENT LOG] %(message)s')

# endereco base do servidor
SERVER_URL = "http://127.0.0.1:5000"

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
    username = input("escolha um nome de usuario: ")
    password = getpass.getpass("escolha uma senha: ")
    
    if os.path.exists(get_client_salt_path(username)):
        logging.error("usuario ja registrado neste cliente.")
        return

    client_salt = crypto_utils.generate_salt()
    pbkdf2_token = crypto_utils.derive_pbkdf2_token(password, client_salt)
    
    payload = {
        "username": username,
        "pbkdf2_token_b64": base64.b64encode(pbkdf2_token).decode('utf-8')
    }
    
    try:
        logging.info(f"enviando solicitacao de registro para '{username}' ao servidor...")
        response = requests.post(f"{SERVER_URL}/register", json=payload)
        response_data = response.json()

        if response.status_code == 200 and response_data.get("success"):
            logging.info(f"sucesso: {response_data['message']}")
            save_client_salt(username, client_salt)
            totp_secret = response_data['totp_secret']
            uri = crypto_utils.get_totp_uri(username, totp_secret)
            crypto_utils.display_qr_code(uri)
            print("\nimportante: escaneie o qr code com google authenticator ou similar.")
        else:
            logging.error(f"falha no registro: {response_data.get('message', 'erro desconhecido')}")
    except requests.exceptions.RequestException as e:
        logging.error(f"erro de comunicacao com o servidor: {e}")

def handle_login():
    username = input("usuario: ")
    password = getpass.getpass("senha: ")

    client_salt = load_client_salt(username)
    if not client_salt:
        logging.error("falha na autenticacao: usuario nao encontrado neste cliente.")
        return

    # etapa 1: autenticacao com senha
    logging.info("derivando token e enviando para autenticacao (etapa 1)...")
    pbkdf2_token = crypto_utils.derive_pbkdf2_token(password, client_salt)
    payload_step1 = {
        "username": username,
        "pbkdf2_token_b64": base64.b64encode(pbkdf2_token).decode('utf-8')
    }
    
    try:
        response_step1 = requests.post(f"{SERVER_URL}/auth/step1", json=payload_step1)
        if not response_step1.json().get("authenticated"):
            logging.error("falha na autenticacao: usuario ou senha invalidos.")
            return

        # etapa 2: autenticacao com totp
        logging.info("senha verificada. por favor, insira o codigo 2fa.")
        totp_code = input("codigo de autenticacao (6 digitos): ")
        payload_step2 = {"username": username, "totp_code": totp_code}
        
        response_step2 = requests.post(f"{SERVER_URL}/auth/step2", json=payload_step2)
        if not response_step2.json().get("authenticated"):
            logging.error("falha na autenticacao: codigo invalido.")
            return

        logging.info("login bem-sucedido!")
        logged_in_menu(username, password, client_salt)

    except requests.exceptions.RequestException as e:
        logging.error(f"erro de comunicacao com o servidor: {e}")

def logged_in_menu(username, password, client_salt):
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
            logging.info("logout realizado.")
            break
        else:
            print("opcao invalida.")

def handle_upload(username, password, client_salt):
    filepath = input("caminho do arquivo para enviar: ")
    if not os.path.exists(filepath):
        logging.error("arquivo nao encontrado.")
        return

    filename = os.path.basename(filepath)
    with open(filepath, 'rb') as f:
        file_data = f.read()

    logging.info("derivando chave e cifrando o arquivo...")
    encryption_key = crypto_utils.derive_pbkdf2_token(password, client_salt)
    encrypted_content = crypto_utils.encrypt_aes_gcm(file_data, encryption_key)
    
    payload = {
        "username": username,
        "filename": filename,
        "encrypted_content": encrypted_content # ja e um dicionario com strings base64
    }
    
    try:
        logging.info(f"enviando arquivo '{filename}' para o servidor...")
        response = requests.post(f"{SERVER_URL}/files/upload", json=payload)
        if response.json().get("success"):
            logging.info(f"arquivo '{filename}' enviado com sucesso.")
        else:
            logging.error("falha ao enviar o arquivo.")
    except requests.exceptions.RequestException as e:
        logging.error(f"erro de comunicacao com o servidor: {e}")

def handle_download(username, password, client_salt):
    filename = input("nome do arquivo para baixar: ")
    
    payload = {"username": username, "filename": filename}
    
    try:
        logging.info(f"solicitando o arquivo '{filename}' do servidor...")
        response = requests.post(f"{SERVER_URL}/files/download", json=payload)
        response_data = response.json()

        if not response_data.get("success"):
            logging.error(f"arquivo nao encontrado no servidor: {response_data.get('message')}")
            return
        
        encrypted_content = response_data.get('encrypted_content')
        logging.info("arquivo recebido. derivando chave e decifrando...")
        decryption_key = crypto_utils.derive_pbkdf2_token(password, client_salt)
        decrypted_data = crypto_utils.decrypt_aes_gcm(encrypted_content, decryption_key)

        if decrypted_data:
            print("\n--- conteudo do arquivo decifrado ---")
            try:
                print(decrypted_data.decode('utf-8'))
            except UnicodeDecodeError:
                print(f"(dados binarios): {decrypted_data}")
            print("------------------------------------")
        else:
            logging.error("falha ao decifrar o arquivo. a senha pode estar incorreta ou o arquivo corrompido.")
            
    except requests.exceptions.RequestException as e:
        logging.error(f"erro de comunicacao com o servidor: {e}")

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


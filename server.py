import os
import json
import base64
import crypto_utils

# simulacao de um banco de dados de usuarios e arquivos usando arquivos json
DB_USERS_FILE = "server_db_users.json"
DB_FILES_FILE = "server_db_files.json"

def init_db():
    # inicializa os arquivos de 'banco de dados' se nao existirem
    if not os.path.exists(DB_USERS_FILE):
        with open(DB_USERS_FILE, 'w') as f:
            json.dump({}, f)
    if not os.path.exists(DB_FILES_FILE):
        with open(DB_FILES_FILE, 'w') as f:
            json.dump({}, f)

def load_db(file_path):
    with open(file_path, 'r') as f:
        return json.load(f)

def save_db(data, file_path):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def register_user(username, pbkdf2_token):
    # registra um novo usuario no servidor
    db_users = load_db(DB_USERS_FILE)
    if username in db_users:
        return None, "usuario ja existe."

    # gera o salt do scrypt, o segredo totp e deriva o token final
    scrypt_salt = crypto_utils.generate_salt()
    scrypt_token_final = crypto_utils.derive_scrypt_token(pbkdf2_token, scrypt_salt)
    totp_secret = crypto_utils.generate_totp_secret()

    db_users[username] = {
        "scrypt_salt_b64": base64.b64encode(scrypt_salt).decode('utf-8'),
        "scrypt_token_b64": base64.b64encode(scrypt_token_final).decode('utf-8'),
        "totp_secret": totp_secret
    }
    save_db(db_users, DB_USERS_FILE)
    return totp_secret, "usuario registrado com sucesso."

def authenticate_step1(username, pbkdf2_token):
    # primeira etapa da autenticacao: verifica o token derivado de login/senha
    db_users = load_db(DB_USERS_FILE)
    user_data = db_users.get(username)
    if not user_data:
        return False

    scrypt_salt = base64.b64decode(user_data["scrypt_salt_b64"])
    stored_scrypt_token = base64.b64decode(user_data["scrypt_token_b64"])
    
    # deriva o token recebido com o salt armazenado
    scrypt_token_to_check = crypto_utils.derive_scrypt_token(pbkdf2_token, scrypt_salt)

    return scrypt_token_to_check == stored_scrypt_token

def authenticate_step2(username, totp_code):
    # segunda etapa da autenticacao: verifica o codigo totp
    db_users = load_db(DB_USERS_FILE)
    user_data = db_users.get(username)
    if not user_data:
        return False
    
    return crypto_utils.verify_totp_code(user_data["totp_secret"], totp_code)

def store_file(username, filename, encrypted_content):
    # armazena um arquivo cifrado para um usuario
    db_files = load_db(DB_FILES_FILE)
    if username not in db_files:
        db_files[username] = {}
    
    db_files[username][filename] = encrypted_content
    save_db(db_files, DB_FILES_FILE)
    print("arquivo armazenado no servidor.")

def retrieve_file(username, filename):
    # recupera um arquivo cifrado
    db_files = load_db(DB_FILES_FILE)
    return db_files.get(username, {}).get(filename)

# inicializa o 'banco de dados' ao iniciar o servidor
init_db()

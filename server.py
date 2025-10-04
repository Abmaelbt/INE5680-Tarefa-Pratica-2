import os
import json
import base64
import crypto_utils
from flask import Flask, request, jsonify, abort

# inicializa o servidor web flask
app = Flask(__name__)

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

# --- endpoints da api ---

@app.route('/register', methods=['POST'])
def route_register():
    data = request.json
    username = data.get('username')
    pbkdf2_token_b64 = data.get('pbkdf2_token_b64')
    
    print(f"[LOG] recebida solicitacao de registro para o usuario: {username}")

    if not username or not pbkdf2_token_b64:
        abort(400, description="usuario ou token nao fornecidos.")

    db_users = load_db(DB_USERS_FILE)
    if username in db_users:
        return jsonify({"success": False, "message": "usuario ja existe."}), 409

    pbkdf2_token = base64.b64decode(pbkdf2_token_b64)
    scrypt_salt = crypto_utils.generate_salt()
    scrypt_token_final = crypto_utils.derive_scrypt_token(pbkdf2_token, scrypt_salt)
    totp_secret = crypto_utils.generate_totp_secret()

    db_users[username] = {
        "scrypt_salt_b64": base64.b64encode(scrypt_salt).decode('utf-8'),
        "scrypt_token_b64": base64.b64encode(scrypt_token_final).decode('utf-8'),
        "totp_secret": totp_secret
    }
    save_db(db_users, DB_USERS_FILE)
    
    print(f"[LOG] usuario {username} registrado com sucesso.")
    return jsonify({
        "success": True, 
        "message": "usuario registrado com sucesso.",
        "totp_secret": totp_secret
    })

@app.route('/auth/step1', methods=['POST'])
def route_auth_step1():
    data = request.json
    username = data.get('username')
    pbkdf2_token_b64 = data.get('pbkdf2_token_b64')
    print(f"[LOG] recebida tentativa de login (etapa 1) para: {username}")

    db_users = load_db(DB_USERS_FILE)
    user_data = db_users.get(username)
    if not user_data:
        return jsonify({"authenticated": False}), 401

    scrypt_salt = base64.b64decode(user_data["scrypt_salt_b64"])
    stored_scrypt_token = base64.b64decode(user_data["scrypt_token_b64"])
    
    pbkdf2_token = base64.b64decode(pbkdf2_token_b64)
    scrypt_token_to_check = crypto_utils.derive_scrypt_token(pbkdf2_token, scrypt_salt)

    authenticated = scrypt_token_to_check == stored_scrypt_token
    if authenticated:
        print(f"[LOG] usuario {username} passou na etapa 1.")
    else:
        print(f"[LOG] falha na etapa 1 para {username}.")
        
    return jsonify({"authenticated": authenticated})

@app.route('/auth/step2', methods=['POST'])
def route_auth_step2():
    data = request.json
    username = data.get('username')
    totp_code = data.get('totp_code')
    print(f"[LOG] recebida tentativa de login (etapa 2) para: {username}")

    db_users = load_db(DB_USERS_FILE)
    user_data = db_users.get(username)
    if not user_data:
        return jsonify({"authenticated": False}), 401

    authenticated = crypto_utils.verify_totp_code(user_data["totp_secret"], totp_code)
    if authenticated:
        print(f"[LOG] usuario {username} autenticado com sucesso (2fa).")
    else:
        print(f"[LOG] falha na etapa 2 (2fa) para {username}.")
        
    return jsonify({"authenticated": authenticated})

@app.route('/files/upload', methods=['POST'])
def route_upload_file():
    data = request.json
    username = data.get('username')
    filename = data.get('filename')
    encrypted_content = data.get('encrypted_content')
    print(f"[LOG] recebida solicitacao de upload do arquivo '{filename}' para o usuario '{username}'")
    
    db_files = load_db(DB_FILES_FILE)
    if username not in db_files:
        db_files[username] = {}
    
    db_files[username][filename] = encrypted_content
    save_db(db_files, DB_FILES_FILE)
    
    print(f"[LOG] arquivo '{filename}' armazenado com sucesso.")
    return jsonify({"success": True, "message": "arquivo armazenado no servidor."})

@app.route('/files/download', methods=['POST'])
def route_download_file():
    data = request.json
    username = data.get('username')
    filename = data.get('filename')
    print(f"[LOG] recebida solicitacao de download do arquivo '{filename}' para '{username}'")

    db_files = load_db(DB_FILES_FILE)
    encrypted_content = db_files.get(username, {}).get(filename)

    if not encrypted_content:
        return jsonify({"success": False, "message": "arquivo nao encontrado."}), 404
        
    print(f"[LOG] enviando arquivo '{filename}' para o cliente.")
    return jsonify({"success": True, "encrypted_content": encrypted_content})


if __name__ == '__main__':
    init_db()
    print("servidor iniciado em http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=False)


import os
import base64
import hashlib
import json

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import pyotp
import qrcode
from PIL import Image
import io

# configuracoes gerais de criptografia
SALT_SIZE = 16
KEY_SIZE = 32 # para aes-256
PBKDF2_ITERATIONS = 480000
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

def generate_salt():
    # gera um salt aleatorio para ser usado nas derivacoes de chave
    return os.urandom(SALT_SIZE)

def derive_pbkdf2_token(password, salt):
    # deriva um token usando pbkdf2 - usado no cliente
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    return kdf.derive(password.encode())

def derive_scrypt_token(token, salt):
    # deriva um token usando scrypt - usado no servidor
    return hashlib.scrypt(
        token,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_SIZE
    )

def encrypt_aes_gcm(data, key):
    # cifra os dados usando aes-gcm para garantir confidencialidade e autenticidade
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return {
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }

def decrypt_aes_gcm(encrypted_data, key):
    # decifra os dados usando aes-gcm
    try:
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"erro ao decifrar: {e}")
        return None

def generate_totp_secret():
    # gera um segredo para o segundo fator de autenticacao
    return pyotp.random_base32()

def get_totp_uri(username, secret):
    # retorna a uri para gerar o qr code
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="AppNuvemSegura"
    )

def verify_totp_code(secret, code):
    # verifica se o codigo totp fornecido e valido
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def display_qr_code(uri):
    # exibe o qr code no terminal ou abre em um visualizador de imagem
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    
    # tenta abrir a imagem, se nao conseguir, imprime no console
    try:
        img.show()
        print("qr code aberto no visualizador de imagens. escaneie com seu app de autenticacao.")
    except Exception:
        print("nao foi possivel abrir o qr code. copie a uri abaixo para seu app de autenticacao:")
        print(uri)

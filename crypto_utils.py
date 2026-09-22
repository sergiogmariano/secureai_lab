"""
Camada criptográfica do SecureAI Lab.

Cada função abaixo responde a UMA das exigências do briefing
("Como a criptografia deverá ser aplicada?"):

  1. Simétrica  -> proteger dados sensíveis em repouso (campos do prontuário).
  2. Assimétrica-> assinatura digital dos registros de auditoria (não-repúdio).
  3. Hash       -> integridade de arquivos de exame (SHA-256).
  4. Senhas     -> bcrypt (hash lento + salt) — NUNCA hash puro nem texto claro.
  5. Chaves     -> geradas fora do código, guardadas em keys/ (fora do git),
                   carregadas sob demanda. Rotação = gerar novo par/arquivo.
"""
import os
import base64
import hashlib

import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from config import Config


# =====================================================================
# 1) SENHAS  — bcrypt (fator de trabalho embutido, salt automático)
# =====================================================================
def hash_password(plain: str) -> str:
    """Gera hash bcrypt. bcrypt já inclui salt aleatório de 16 bytes."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# =====================================================================
# 5) GESTÃO DE CHAVES — geração/carga
# =====================================================================
def ensure_keys():
    """Cria as chaves na primeira execução, se ainda não existirem."""
    os.makedirs(os.path.dirname(Config.FERNET_KEY_PATH), exist_ok=True)

    # ---- Chave simétrica (Fernet) ----
    if not os.path.exists(Config.FERNET_KEY_PATH):
        with open(Config.FERNET_KEY_PATH, "wb") as f:
            f.write(Fernet.generate_key())
        os.chmod(Config.FERNET_KEY_PATH, 0o600)  # só o dono lê

    # ---- Par RSA (assimétrico) ----
    if not (os.path.exists(Config.RSA_PRIVATE_KEY_PATH)
            and os.path.exists(Config.RSA_PUBLIC_KEY_PATH)):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(Config.RSA_PRIVATE_KEY_PATH, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        os.chmod(Config.RSA_PRIVATE_KEY_PATH, 0o600)
        with open(Config.RSA_PUBLIC_KEY_PATH, "wb") as f:
            f.write(priv.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))


def _load_fernet() -> Fernet:
    with open(Config.FERNET_KEY_PATH, "rb") as f:
        return Fernet(f.read())


def _load_rsa_private():
    with open(Config.RSA_PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_rsa_public():
    with open(Config.RSA_PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# =====================================================================
# 1) SIMÉTRICA — proteção de dados sensíveis em repouso
# =====================================================================
def encrypt_field(plaintext: str) -> str:
    """Cifra um campo sensível (ex.: CPF, diagnóstico) para gravar no banco."""
    if plaintext is None:
        return None
    return _load_fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_field(token: str) -> str:
    if token is None:
        return None
    try:
        return _load_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except Exception:
        return "[dado ilegível]"


# =====================================================================
# 3) HASH — integridade de arquivos (SHA-256)
# =====================================================================
def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# =====================================================================
# 2) ASSIMÉTRICA — assinatura digital (integridade + autenticidade + não-repúdio)
# =====================================================================
def sign_record(message: str) -> str:
    """Assina uma linha de auditoria com a chave privada RSA (RSA-PSS + SHA-256)."""
    priv = _load_rsa_private()
    signature = priv.sign(
        message.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("utf-8")


def verify_record(message: str, signature_b64: str) -> bool:
    """Verifica a assinatura usando a chave pública (qualquer auditor pode)."""
    try:
        pub = _load_rsa_public()
        pub.verify(
            base64.b64decode(signature_b64),
            message.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

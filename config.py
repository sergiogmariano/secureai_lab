"""
Configuração central da aplicação SecureAI Lab.

A flag VULNERABLE_MODE é o coração da demonstração acadêmica:
- VULNERABLE_MODE=1  -> reativa os caminhos de código inseguros (estado "antes").
- VULNERABLE_MODE=0  -> caminhos corrigidos e endurecidos (estado "depois").

Isso permite rodar o MESMO script de pentest contra os dois estados e provar:
    Ataque funcionando -> correção -> ataque bloqueado.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


def load_env_file(path=os.path.join(BASE_DIR, ".env")):
    """Carrega variáveis do .env (formato CHAVE=valor) para os.environ.

    Não sobrescreve variáveis já definidas no ambiente, para que scripts como
    pentest.py possam alternar VULNERABLE_MODE livremente.
    """
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip().strip('"').strip("'")
            if key and value:
                os.environ.setdefault(key, value)


load_env_file()

# No Vercel (serverless) só /tmp é gravável e nada persiste entre deploys:
# banco, chaves e uploads vão para /tmp e são recriados quando necessário.
DATA_DIR = "/tmp/secureai_lab" if os.environ.get("VERCEL") else BASE_DIR


class Config:
    # --- Flags de demonstração ------------------------------------------
    # Lê a variável de ambiente na hora do request (ver helper is_vulnerable)
    VULNERABLE_MODE_DEFAULT = os.environ.get("VULNERABLE_MODE", "0") == "1"

    # --- Segredos / chaves ----------------------------------------------
    # Em produção viriam de um cofre (Vault/KMS), NUNCA versionadas em git.
    SECRET_KEY = os.environ.get("APP_SECRET_KEY", "troque-isto-em-producao-32bytes!!")
    JWT_SECRET = os.environ.get("JWT_SECRET", "jwt-troque-isto-em-producao-256bit")
    JWT_EXP_MINUTES = 30

    # Chave da criptografia simétrica (Fernet/AES-128-CBC + HMAC).
    # Gerada uma vez e guardada em keys/fernet.key (fora do controle de versão).
    FERNET_KEY_PATH = os.path.join(DATA_DIR, "keys", "fernet.key")

    # Par de chaves RSA para assinatura digital dos registros de auditoria.
    RSA_PRIVATE_KEY_PATH = os.path.join(DATA_DIR, "keys", "rsa_private.pem")
    RSA_PUBLIC_KEY_PATH = os.path.join(DATA_DIR, "keys", "rsa_public.pem")

    # --- Banco / arquivos ------------------------------------------------
    DB_PATH = os.path.join(DATA_DIR, "instance", "clinica.db")
    UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
    ALLOWED_UPLOAD_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".txt"}
    MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB

    # --- Cookies de sessão (hardening) ----------------------------------
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # SECURE só em HTTPS real; em localhost HTTP fica False para não quebrar a demo.
    SESSION_COOKIE_SECURE = os.environ.get("HTTPS_ENABLED", "0") == "1"

    # --- IA --------------------------------------------------------------
    # Se houver chave, usa a API real; senão, cai no classificador local.
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
    AI_MODEL = "claude-sonnet-4-6"


def is_vulnerable():
    """Lê a flag em tempo de request para permitir alternar sem reiniciar em testes."""
    return os.environ.get("VULNERABLE_MODE", "0") == "1"

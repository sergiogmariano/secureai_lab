"""
Camada de acesso a dados (SQLite).

Modelo de dados (Portal de Clínica):
  users        -> credenciais + papel (RBAC)
  patients     -> dados pessoais/sensíveis (alguns cifrados em repouso)
  exams        -> arquivos de exame + hash SHA-256 (integridade)
  notes        -> anotações clínicas (campo alvo do XSS armazenado)
  audit_log    -> eventos de segurança, cada linha ASSINADA com RSA

Observação didática: usamos sqlite3 puro (não um ORM) de propósito, para
mostrar lado a lado a consulta VULNERÁVEL (concatenação) e a CORRIGIDA
(parametrizada) na demonstração de SQL Injection.
"""
import os
import sqlite3
import datetime

from config import Config
from crypto_utils import (hash_password, encrypt_field, sign_record)


def get_conn():
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
    conn = get_conn()
    c = conn.cursor()
    c.executescript(
        """
        DROP TABLE IF EXISTS audit_log;
        DROP TABLE IF EXISTS notes;
        DROP TABLE IF EXISTS exams;
        DROP TABLE IF EXISTS patients;
        DROP TABLE IF EXISTS users;

        CREATE TABLE users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,   -- estado SEGURO: bcrypt (salt + custo)
            password_plain TEXT,           -- estado VULNERÁVEL: texto puro (má prática!)
            role          TEXT NOT NULL CHECK(role IN ('patient','admin')),
            failed_logins INTEGER NOT NULL DEFAULT 0,
            locked_until  TEXT
        );

        CREATE TABLE patients (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            full_name     TEXT NOT NULL,
            cpf_enc       TEXT NOT NULL,   -- CPF cifrado (simétrica)
            diagnosis_enc TEXT,            -- diagnóstico cifrado (simétrica)
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE exams (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id   INTEGER NOT NULL,
            filename     TEXT NOT NULL,
            stored_name  TEXT NOT NULL,
            sha256       TEXT NOT NULL,   -- integridade do arquivo
            uploaded_at  TEXT NOT NULL,
            FOREIGN KEY(patient_id) REFERENCES patients(id)
        );

        CREATE TABLE notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id  INTEGER NOT NULL,
            author      TEXT NOT NULL,
            body        TEXT NOT NULL,   -- alvo do XSS armazenado
            created_at  TEXT NOT NULL,
            FOREIGN KEY(patient_id) REFERENCES patients(id)
        );

        CREATE TABLE audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            actor       TEXT,
            action      TEXT NOT NULL,
            detail      TEXT,
            signature   TEXT NOT NULL    -- assinatura RSA da linha (não-repúdio)
        );
        """
    )
    conn.commit()
    conn.close()


def add_audit(actor, action, detail=""):
    """Grava um evento de segurança e ASSINA digitalmente a linha."""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    canonical = f"{ts}|{actor}|{action}|{detail}"
    signature = sign_record(canonical)
    conn = get_conn()
    conn.execute(
        "INSERT INTO audit_log (ts, actor, action, detail, signature) VALUES (?,?,?,?,?)",
        (ts, actor, action, detail, signature),
    )
    conn.commit()
    conn.close()


# ------------------------------------------------------------------ #
#  ANONIMIZAÇÃO / PSEUDONIMIZAÇÃO / MASCARAMENTO (LGPD)
# ------------------------------------------------------------------ #
def mask_cpf(cpf: str) -> str:
    """Mascaramento: exibe apenas os 3 dígitos finais -> ***.***.**9-99."""
    digits = "".join(ch for ch in cpf if ch.isdigit())
    if len(digits) != 11:
        return "***"
    return f"***.***.{digits[8]}{digits[9]}-{digits[10]}... (mascarado)"


def pseudonymize(name: str, salt: str = "clinica2025") -> str:
    """Pseudonimização determinística p/ datasets de teste (reversível só com o salt/tabela)."""
    import hashlib
    return "PAC-" + hashlib.sha256((salt + name).encode()).hexdigest()[:10].upper()


def seed():
    """Popula o banco com dados FICTÍCIOS (nenhum dado real)."""
    init_db()
    conn = get_conn()
    c = conn.cursor()

    # Usuários: 1 admin (médico) + 3 pacientes
    users = [
        ("dra.nigro", "Admin@Clinica2025", "admin"),
        ("ana.paciente", "AnaSenha@123", "patient"),
        ("bruno.paciente", "BrunoSenha@123", "patient"),
        ("carla.paciente", "CarlaSenha@123", "patient"),
    ]
    user_ids = {}
    for username, pwd, role in users:
        # password_hash (bcrypt) é o correto; password_plain existe só para
        # reproduzir o "estado antes" (armazenamento em texto puro) na demo.
        c.execute(
            "INSERT INTO users (username, password_hash, password_plain, role) VALUES (?,?,?,?)",
            (username, hash_password(pwd), pwd, role),
        )
        user_ids[username] = c.lastrowid

    # Pacientes (CPF e diagnóstico CIFRADOS em repouso)
    patients = [
        ("ana.paciente",   "Ana Souza Lima",     "123.456.789-09", "Hipertensão arterial estágio 1"),
        ("bruno.paciente", "Bruno Alves Costa",  "987.654.321-00", "Diabetes tipo 2"),
        ("carla.paciente", "Carla Menezes Rocha","111.222.333-96", "Asma leve intermitente"),
    ]
    pat_ids = {}
    for uname, name, cpf, diag in patients:
        c.execute(
            "INSERT INTO patients (user_id, full_name, cpf_enc, diagnosis_enc) VALUES (?,?,?,?)",
            (user_ids[uname], name, encrypt_field(cpf), encrypt_field(diag)),
        )
        pat_ids[uname] = c.lastrowid

    # Uma anotação clínica benigna por paciente
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for uname in pat_ids:
        c.execute(
            "INSERT INTO notes (patient_id, author, body, created_at) VALUES (?,?,?,?)",
            (pat_ids[uname], "dra.nigro", "Retorno em 30 dias. Manter medicação.", now),
        )

    conn.commit()
    conn.close()

    # Auditoria inicial assinada
    add_audit("system", "SEED", "Banco populado com dados fictícios")
    print("Banco populado. Logins de teste:")
    for u, p, r in users:
        print(f"  {u:16s} / {p:20s} ({r})")


if __name__ == "__main__":
    from crypto_utils import ensure_keys
    ensure_keys()
    seed()

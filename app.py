"""
SecureAI Lab — Portal de Clínica
Aplicação web funcional com ciclo Desenvolvimento -> Ataque -> Correção -> Reteste.

Cada vulnerabilidade tem os DOIS caminhos no código, selecionados por
config.is_vulnerable() (env VULNERABLE_MODE):
  - SQL Injection (login)        -> rota /login
  - Broken Access Control / IDOR -> rota /paciente/<id>
  - XSS armazenado               -> notas clínicas (/paciente/<id>/nota)
  - Upload inseguro de arquivos  -> rota /paciente/<id>/exame
  - Prompt Injection (IA)        -> ai_service.triage()
"""
import os
import uuid
import functools
import datetime

import jwt
from flask import (Flask, request, redirect, url_for, render_template,
                   session, abort, send_file, flash, g, Response)
from markupsafe import escape

from config import Config, is_vulnerable
from crypto_utils import (ensure_keys, verify_password, decrypt_field,
                          sha256_file, verify_record)
from db import (get_conn, add_audit, mask_cpf)
from ai_service import triage

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

ensure_keys()  # garante chaves na inicialização
# Em ambiente serverless (Vercel) não há "python app.py": cria pasta de uploads
# e popula o banco na primeira importação, se ainda não existir.
os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
if not os.path.exists(Config.DB_PATH):
    from db import seed
    seed()


# ===================================================================== #
#  Cabeçalhos de segurança (hardening) — aplicados a toda resposta
# ===================================================================== #
@app.after_request
def security_headers(resp):
    if not is_vulnerable():
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # CSP restritiva: mitiga XSS mesmo que algo escape
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


# ===================================================================== #
#  Autenticação por sessão + JWT para a API
# ===================================================================== #
def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    conn = get_conn()
    u = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return u


def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **k):
        if not current_user():
            return redirect(url_for("login"))
        return view(*a, **k)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*a, **k):
        u = current_user()
        if not u:
            return redirect(url_for("login"))
        if u["role"] != "admin":
            add_audit(u["username"], "ACCESS_DENIED", f"tentou acessar {request.path}")
            abort(403)
        return view(*a, **k)
    return wrapped


def make_jwt(user):
    payload = {
        "sub": user["id"], "username": user["username"], "role": user["role"],
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=Config.JWT_EXP_MINUTES),
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")


def decode_jwt(token):
    # SEGURO: exige algoritmo explícito (bloqueia ataque alg=none).
    # VULNERÁVEL: aceitaria qualquer coisa (não fazemos isso nem no modo demo por segurança do avaliador).
    return jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])


# ===================================================================== #
#  Rotas
# ===================================================================== #
@app.route("/")
def index():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    if u["role"] == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("meu_prontuario"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", vulnerable=is_vulnerable())

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_conn()

    if is_vulnerable():
        # -------- VULNERÁVEL: SQL Injection (concatenação de strings) --------
        # Também demonstra armazenamento de senha em texto puro (password_plain).
        # Login normal funciona; payload "dra.nigro' -- " comenta a checagem de senha.
        query = ("SELECT * FROM users WHERE username = '%s' AND password_plain = '%s'"
                 % (username, password))
        try:
            row = conn.execute(query).fetchone()
        except Exception:
            row = None
        conn.close()
        if row:
            session["uid"] = row["id"]
            add_audit(username, "LOGIN_OK", "modo vulneravel")
            return redirect(url_for("index"))
        flash("Credenciais inválidas.")
        return render_template("login.html", vulnerable=True)

    # -------- SEGURO: consulta parametrizada + bcrypt + lockout --------
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    # Bloqueio por tentativas (proteção contra brute force)
    if row and row["locked_until"]:
        if row["locked_until"] > datetime.datetime.now(datetime.timezone.utc).isoformat():
            conn.close()
            add_audit(username, "LOGIN_LOCKED", "conta bloqueada temporariamente")
            flash("Conta temporariamente bloqueada. Tente mais tarde.")
            return render_template("login.html", vulnerable=False)

    if row and verify_password(password, row["password_hash"]):
        conn.execute("UPDATE users SET failed_logins=0, locked_until=NULL WHERE id=?",
                     (row["id"],))
        conn.commit()
        conn.close()
        session.clear()
        session["uid"] = row["id"]
        add_audit(username, "LOGIN_OK", "")
        return redirect(url_for("index"))

    # Falha: incrementa contador; bloqueia após 5
    if row:
        fails = row["failed_logins"] + 1
        locked = None
        if fails >= 5:
            locked = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)).isoformat()
        conn.execute("UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                     (fails, locked, row["id"]))
        conn.commit()
    conn.close()
    add_audit(username, "LOGIN_FAIL", "credenciais invalidas")
    flash("Credenciais inválidas.")  # mensagem genérica (não revela se user existe)
    return render_template("login.html", vulnerable=False)


@app.route("/logout")
def logout():
    u = current_user()
    if u:
        add_audit(u["username"], "LOGOUT", "")
    session.clear()
    return redirect(url_for("login"))


# ---------- Área do PACIENTE ----------
@app.route("/meu-prontuario")
@login_required
def meu_prontuario():
    u = current_user()
    conn = get_conn()
    pat = conn.execute("SELECT * FROM patients WHERE user_id=?", (u["id"],)).fetchone()
    if not pat:
        conn.close()
        # admin não tem prontuário próprio
        return redirect(url_for("admin_dashboard")) if u["role"] == "admin" else abort(404)
    exams = conn.execute("SELECT * FROM exams WHERE patient_id=? ORDER BY id DESC",
                         (pat["id"],)).fetchall()
    notes = conn.execute("SELECT * FROM notes WHERE patient_id=? ORDER BY id DESC",
                         (pat["id"],)).fetchall()
    conn.close()
    return render_template("prontuario.html", u=u, pat=pat,
                           cpf=mask_cpf(decrypt_field(pat["cpf_enc"])),
                           diagnosis=decrypt_field(pat["diagnosis_enc"]),
                           exams=exams, notes=notes, vulnerable=is_vulnerable(),
                           can_edit=False)


# ---------- Acesso a prontuário por ID (alvo de IDOR) ----------
@app.route("/paciente/<int:pid>")
@login_required
def paciente(pid):
    u = current_user()
    conn = get_conn()
    pat = conn.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
    if not pat:
        conn.close()
        abort(404)

    if is_vulnerable():
        # -------- VULNERÁVEL: IDOR — não valida se o prontuário é do usuário --------
        # Qualquer paciente logado abre /paciente/2 e vê dados alheios.
        pass
    else:
        # -------- SEGURO: controle de acesso por propriedade + papel --------
        is_owner = (pat["user_id"] == u["id"])
        if u["role"] != "admin" and not is_owner:
            conn.close()
            add_audit(u["username"], "IDOR_BLOCKED", f"tentou acessar paciente {pid}")
            abort(403)

    exams = conn.execute("SELECT * FROM exams WHERE patient_id=? ORDER BY id DESC",
                         (pid,)).fetchall()
    notes = conn.execute("SELECT * FROM notes WHERE patient_id=? ORDER BY id DESC",
                         (pid,)).fetchall()
    conn.close()
    add_audit(u["username"], "VIEW_PATIENT", f"paciente {pid}")
    return render_template("prontuario.html", u=u, pat=pat,
                           cpf=mask_cpf(decrypt_field(pat["cpf_enc"])),
                           diagnosis=decrypt_field(pat["diagnosis_enc"]),
                           exams=exams, notes=notes, vulnerable=is_vulnerable(),
                           can_edit=(u["role"] == "admin"))


# ---------- Anotação clínica (alvo de XSS armazenado) ----------
@app.route("/paciente/<int:pid>/nota", methods=["POST"])
@login_required
def add_note(pid):
    u = current_user()
    body = request.form.get("body", "")
    conn = get_conn()
    pat = conn.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
    if not pat:
        conn.close(); abort(404)
    # controle de acesso na escrita (só admin ou dono)
    if not is_vulnerable() and u["role"] != "admin" and pat["user_id"] != u["id"]:
        conn.close(); abort(403)

    if is_vulnerable():
        # VULNERÁVEL: grava HTML/JS cru; o template renderiza sem escapar.
        stored = body
    else:
        # SEGURO: sanitiza no armazenamento (defesa 1) — o template também escapa (defesa 2).
        stored = str(escape(body))

    conn.execute("INSERT INTO notes (patient_id, author, body, created_at) VALUES (?,?,?,?)",
                 (pid, u["username"], stored,
                  datetime.datetime.now(datetime.timezone.utc).isoformat()))
    conn.commit(); conn.close()
    add_audit(u["username"], "ADD_NOTE", f"paciente {pid}")
    return redirect(url_for("paciente", pid=pid))


# ---------- Upload de exame (alvo de upload inseguro) ----------
@app.route("/paciente/<int:pid>/exame", methods=["POST"])
@login_required
def upload_exame(pid):
    u = current_user()
    conn = get_conn()
    pat = conn.execute("SELECT * FROM patients WHERE id=?", (pid,)).fetchone()
    if not pat:
        conn.close(); abort(404)
    if not is_vulnerable() and u["role"] != "admin" and pat["user_id"] != u["id"]:
        conn.close(); abort(403)

    f = request.files.get("file")
    if not f or f.filename == "":
        conn.close(); flash("Nenhum arquivo enviado."); return redirect(url_for("paciente", pid=pid))

    original = f.filename
    ext = os.path.splitext(original)[1].lower()

    if is_vulnerable():
        # VULNERÁVEL: salva com o nome original (path traversal) e sem validar extensão/tamanho.
        stored_name = original  # ex.: "../../app.py" ou "shell.php"
        dest = os.path.join(Config.UPLOAD_DIR, stored_name)
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        f.save(dest)
    else:
        # SEGURO: valida extensão + tamanho, gera nome aleatório, calcula hash.
        if ext not in Config.ALLOWED_UPLOAD_EXT:
            conn.close()
            add_audit(u["username"], "UPLOAD_BLOCKED", f"extensao {ext}")
            flash(f"Tipo de arquivo não permitido: {ext}")
            return redirect(url_for("paciente", pid=pid))
        data = f.read()
        if len(data) > Config.MAX_UPLOAD_BYTES:
            conn.close(); flash("Arquivo muito grande."); return redirect(url_for("paciente", pid=pid))
        stored_name = f"{uuid.uuid4().hex}{ext}"
        dest = os.path.join(Config.UPLOAD_DIR, stored_name)
        with open(dest, "wb") as out:
            out.write(data)

    digest = sha256_file(dest)
    conn.execute(
        "INSERT INTO exams (patient_id, filename, stored_name, sha256, uploaded_at) "
        "VALUES (?,?,?,?,?)",
        (pid, original, stored_name, digest, datetime.datetime.now(datetime.timezone.utc).isoformat()))
    conn.commit(); conn.close()
    add_audit(u["username"], "UPLOAD_EXAM", f"paciente {pid} sha256={digest[:12]}...")
    flash(f"Exame enviado. SHA-256: {digest}")
    return redirect(url_for("paciente", pid=pid))


@app.route("/exame/<int:eid>/download")
@login_required
def download_exame(eid):
    u = current_user()
    conn = get_conn()
    ex = conn.execute("SELECT * FROM exams WHERE id=?", (eid,)).fetchone()
    if not ex:
        conn.close(); abort(404)
    pat = conn.execute("SELECT * FROM patients WHERE id=?", (ex["patient_id"],)).fetchone()
    conn.close()
    if not is_vulnerable() and u["role"] != "admin" and pat["user_id"] != u["id"]:
        add_audit(u["username"], "DOWNLOAD_BLOCKED", f"exame {eid}"); abort(403)

    path = os.path.join(Config.UPLOAD_DIR, ex["stored_name"])
    if not os.path.exists(path):
        abort(404)
    # Verificação de integridade no download (SHA-256)
    current_hash = sha256_file(path)
    integrity = "OK" if current_hash == ex["sha256"] else "FALHA - ARQUIVO ALTERADO"
    add_audit(u["username"], "DOWNLOAD_EXAM", f"exame {eid} integridade={integrity}")
    resp = send_file(path, as_attachment=True, download_name=ex["filename"])
    resp.headers["X-Integrity-Check"] = integrity
    return resp


# ---------- IA: triagem de sintomas ----------
@app.route("/triagem", methods=["GET", "POST"])
@login_required
def triagem():
    u = current_user()
    resultado = None
    if request.method == "POST":
        sintomas = request.form.get("sintomas", "")
        resultado = triage(sintomas)
        add_audit(u["username"], "AI_TRIAGE",
                  f"bloqueado={resultado['bloqueado']} motivo={resultado['motivo']}")
    return render_template("triagem.html", u=u, resultado=resultado,
                           vulnerable=is_vulnerable())


# ---------- Painel do ADMIN ----------
@app.route("/admin")
@admin_required
def admin_dashboard():
    u = current_user()
    conn = get_conn()
    pats = conn.execute("SELECT * FROM patients ORDER BY id").fetchall()
    conn.close()
    return render_template("admin.html", u=u, pats=pats, vulnerable=is_vulnerable())


@app.route("/admin/auditoria")
@admin_required
def auditoria():
    u = current_user()
    conn = get_conn()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    # Verifica a assinatura de cada linha (integridade/não-repúdio)
    verified = []
    for r in rows:
        canonical = f"{r['ts']}|{r['actor']}|{r['action']}|{r['detail']}"
        ok = verify_record(canonical, r["signature"])
        verified.append((r, ok))
    return render_template("auditoria.html", u=u, rows=verified)


# ---------- API REST (autenticada por JWT) ----------
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE username=?",
                       (data.get("username", ""),)).fetchone()
    conn.close()
    if row and verify_password(data.get("password", ""), row["password_hash"]):
        add_audit(row["username"], "API_LOGIN_OK", "")
        return {"token": make_jwt(row)}
    add_audit(data.get("username", "?"), "API_LOGIN_FAIL", "")
    return {"error": "credenciais invalidas"}, 401


def jwt_required(view):
    @functools.wraps(view)
    def wrapped(*a, **k):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return {"error": "token ausente"}, 401
        try:
            g.jwt = decode_jwt(auth.split(" ", 1)[1])
        except jwt.PyJWTError:
            return {"error": "token invalido"}, 401
        return view(*a, **k)
    return wrapped


@app.route("/api/pacientes")
@jwt_required
def api_pacientes():
    # Autorização por papel também na API
    if g.jwt.get("role") != "admin":
        add_audit(g.jwt.get("username"), "API_FORBIDDEN", "/api/pacientes")
        return {"error": "acesso negado"}, 403
    conn = get_conn()
    pats = conn.execute("SELECT id, full_name FROM patients").fetchall()
    conn.close()
    return {"pacientes": [dict(p) for p in pats]}


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403,
                           msg="Acesso negado (autorização insuficiente)."), 403


@app.errorhandler(404)
def notfound(e):
    return render_template("error.html", code=404, msg="Recurso não encontrado."), 404


if __name__ == "__main__":
    ensure_keys()
    # Garante a pasta de uploads (evita erro 500 no envio de exame no modo seguro).
    os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
    if not os.path.exists(Config.DB_PATH):
        from db import seed
        seed()
    # Porta configuravel por variavel de ambiente (permite rodar os dois modos
    # ao mesmo tempo em portas diferentes: 5000 vulneravel, 5001 seguro).
    port = int(os.environ.get("FLASK_RUN_PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)

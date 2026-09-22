# SecureAI Lab — Portal de Clínica

Aplicação web funcional desenvolvida para a disciplina **Cibersegurança Aplicada a Dados e IA**.
Demonstra o ciclo completo **Desenvolvimento → Ataque → Correção → Reteste** sobre uma
aplicação real, com um interruptor único (`VULNERABLE_MODE`) que alterna entre o
estado inseguro ("antes") e o corrigido ("depois").

## Contexto

Portal de uma clínica onde **pacientes** consultam o próprio prontuário/exames e um
**médico (admin)** gerencia todos os pacientes. Trata dados pessoais sensíveis (saúde),
o que traz a LGPD para o centro do projeto.

## Como executar

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 1) Popular o banco com dados fictícios
python3 db.py

# 2) Rodar a aplicação (modo SEGURO por padrão)
python3 app.py            # http://127.0.0.1:5000

# Modo vulnerável (para demonstrar os ataques):
VULNERABLE_MODE=1 python3 app.py
```

Contas de teste:

| Usuário        | Senha              | Papel   |
|----------------|--------------------|---------|
| dra.nigro      | Admin@Clinica2025  | admin   |
| ana.paciente   | AnaSenha@123       | patient |
| bruno.paciente | BrunoSenha@123     | patient |
| carla.paciente | CarlaSenha@123     | patient |

## Bateria de testes de segurança (evidências)

```bash
python3 pentest.py          # roda os 5 ataques nos 2 modos -> evidence/pentest_report.txt
python3 make_screenshots.py # gera screenshots das telas -> evidence/*.png
```

## IA (triagem de sintomas)

A funcionalidade de IA classifica a urgência dos sintomas (verde/amarelo/vermelho).
Sem `ANTHROPIC_API_KEY`, usa um classificador local por palavras-chave (self-contained);
com a chave, chama a API real. Em ambos os casos há proteção contra **prompt injection**.

## Requisitos obrigatórios do briefing → onde estão

| Requisito                                   | Arquivo / rota |
|---------------------------------------------|----------------|
| Autenticação                                | `app.py` `/login`, `/api/login` |
| ≥2 níveis de privilégio (paciente/admin)    | `app.py` RBAC (`admin_required`) |
| Banco de dados                              | `db.py` (SQLite) |
| API / endpoints                             | `/api/login`, `/api/pacientes` (JWT) |
| Dados pessoais fictícios                    | `db.py` `seed()` |
| Manipulação de arquivos                     | upload/download de exames |
| HTTPS (quando aplicável)                    | `SESSION_COOKIE_SECURE`, HSTS; ver seção HTTPS |
| Controle de acesso/autorização             | decorators + checagem de propriedade |
| Criptografia simétrica                      | `crypto_utils.encrypt_field` (Fernet) |
| Função hash (integridade)                   | `crypto_utils.sha256_file` (SHA-256) |
| Funcionalidade de IA                        | `/triagem` + `ai_service.py` |
| Logs de eventos de segurança                | `db.add_audit` (assinados com RSA) |

## Vulnerabilidades demonstradas (antes → depois)

| # | Vulnerabilidade            | Rota afetada           | Correção |
|---|----------------------------|------------------------|----------|
| 1 | SQL Injection (login)      | `/login`               | consulta parametrizada + bcrypt + lockout |
| 2 | Broken Access Control/IDOR | `/paciente/<id>`       | checagem de propriedade + papel |
| 3 | XSS armazenado             | notas clínicas         | sanitização + autoescape + CSP |
| 4 | Upload inseguro            | `/paciente/<id>/exame` | allow-list de extensão, nome aleatório, limite, hash |
| 5 | Prompt Injection (IA)      | `/triagem`             | delimitação, filtro, privilégio mínimo, validação de saída |

## HTTPS

Em produção, servir atrás de um proxy TLS (Nginx/Caddy) com certificado válido.
`HTTPS_ENABLED=1` ativa `Secure` nos cookies e o header `Strict-Transport-Security`.

## Segurança das chaves

As chaves (`keys/`) e o banco (`instance/`) **não** são versionados (ver `.gitignore`).
Em produção viriam de um cofre (Vault/KMS) com rotação periódica.

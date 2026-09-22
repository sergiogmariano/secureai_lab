# Registro de Utilização de IA

Conforme exigido pelo briefing ("Como a IA poderá ser utilizada pela equipe?"),
registramos abaixo cada uso de IA no desenvolvimento e na análise de segurança.
A IA foi usada como **ferramenta de apoio**; nenhuma resposta foi aceita sem validação.

> **Modelo de validação adotado:** toda saída da IA foi confrontada com (a) execução
> real do código/teste no ambiente, (b) documentação oficial (OWASP, docs das
> bibliotecas) e (c) revisão manual da equipe. O que não passou nos três filtros foi
> descartado.

---

### Uso 1 — Arquitetura de segurança e escolha do domínio
- **Ferramenta:** Claude (Anthropic)
- **Finalidade:** propor um domínio que cobrisse todos os requisitos obrigatórios.
- **Prompt (resumo):** "Sugira um domínio de aplicação web que envolva naturalmente
  dados pessoais sensíveis, upload de arquivos, dois papéis de usuário e uma
  funcionalidade de IA, adequado a um projeto de cibersegurança."
- **Resposta obtida:** portal de clínica (prontuário + exames + triagem por IA).
- **Aproveitado:** o domínio e o mapeamento requisito→funcionalidade.
- **Descartado:** sugestões de campos clínicos excessivos (fora do escopo).
- **Validação:** conferimos manualmente que cada requisito do briefing tinha
  funcionalidade correspondente (tabela no README).

### Uso 2 — Implementação da camada criptográfica
- **Ferramenta:** Claude
- **Finalidade:** confirmar o uso correto de bcrypt, Fernet e RSA-PSS.
- **Prompt (resumo):** "Como proteger senhas, cifrar campos sensíveis em repouso e
  assinar registros de auditoria em Python com a biblioteca `cryptography`?"
- **Resposta obtida:** bcrypt para senhas; Fernet (AES-CBC+HMAC) para campos; RSA-PSS+SHA-256
  para assinatura.
- **Aproveitado:** a estrutura das funções em `crypto_utils.py`.
- **Descartado:** exemplo inicial usava `hashlib.md5` para senha — **rejeitado** por ser
  inadequado (rápido, sem salt).
- **Validação:** testamos assinar/verificar e cifrar/decifrar; rodamos casos negativos
  (assinatura adulterada → inválida). Confirmado com a documentação da `cryptography`.

### Uso 3 — Identificação de vulnerabilidades a demonstrar
- **Ferramenta:** Claude
- **Finalidade:** priorizar, dentre as 13 categorias do briefing, as mais relevantes
  para a arquitetura.
- **Prompt (resumo):** "Dada uma app Flask com login, prontuário por ID, upload de
  arquivos e IA de triagem, quais vulnerabilidades OWASP são mais pertinentes?"
- **Resposta obtida:** SQLi, Broken Access Control/IDOR, XSS armazenado, upload inseguro,
  prompt injection.
- **Aproveitado:** a seleção das 5 vulnerabilidades.
- **Descartado:** sugestão de incluir SSRF (não há requisições a URLs controladas pelo
  usuário na app — não se aplica).
- **Validação:** mapeamos cada vulnerabilidade a um ponto real do código e escrevemos um
  teste automatizado que a reproduz (`pentest.py`).

### Uso 4 — Redação do filtro anti prompt-injection
- **Ferramenta:** Claude
- **Finalidade:** obter padrões comuns de tentativas de injeção de prompt.
- **Prompt (resumo):** "Liste padrões típicos de prompt injection em português e inglês
  para detecção por regex."
- **Resposta obtida:** lista de padrões ("ignore as instruções", "revele o prompt", etc.).
- **Aproveitado:** os padrões em `ai_service.INJECTION_PATTERNS`.
- **Descartado:** confiar **apenas** no regex. A equipe reforçou com defesa em
  profundidade (delimitação do input, privilégio mínimo, validação de saída), pois filtro
  por lista negra é contornável.
- **Validação:** o teste `attack_prompt_injection` confirma bloqueio; documentamos a
  limitação do regex no relatório.

### Uso 5 — Revisão do texto do relatório
- **Ferramenta:** Claude
- **Finalidade:** revisar clareza e estrutura do relatório técnico.
- **Aproveitado:** organização das seções.
- **Descartado:** trechos genéricos sem evidência (substituídos por dados reais dos testes).
- **Validação:** todos os números e evidências citados vêm de execuções reais
  (`evidence/pentest_report.txt` e screenshots).

---

**Conclusão sobre o uso de IA:** a IA acelerou pesquisa e prototipação, mas **todas** as
decisões de segurança foram validadas por execução real e revisão humana. O caso mais
ilustrativo foi o **Uso 2**, em que uma sugestão insegura (MD5 para senha) foi detectada
e rejeitada pela equipe — evidência de que a saída da IA não deve ser aceita
automaticamente.

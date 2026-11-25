# Política de segurança

## Reportando uma vulnerabilidade

Encontrou uma falha no Sentinela? **Não abra uma issue pública.**

Use o reporte privado do GitHub: aba **Security** → **Report a vulnerability**.
Respondo em até 7 dias e, se a falha for confirmada, publico a correção com crédito
a quem reportou (se desejar).

## Modelo de ameaça

O Sentinela processa logs cujo conteúdo é **controlado pelo atacante** (URLs,
User-Agents, nomes de usuário SSH). Por isso:

| Risco | Mitigação |
|-------|-----------|
| XSS no relatório HTML via payloads dos logs | Todo conteúdo passa por `html.escape` (teste `test_html_report_escapes_log_content`) |
| Injeção de sequências ANSI/OSC no terminal do analista | Caracteres de controle C0/C1 são neutralizados antes de imprimir (`cli.safe`) |
| ReDoS com linhas maliciosas | Regex sem quantificadores aninhados e com repetição limitada (teste `test_signatures_resist_redos`) |
| Arquivos `.gz` enormes | Leitura em streaming, linha a linha |
| Cadeia de suprimentos | Zero dependências em tempo de execução; actions do CI fixadas por hash |

Fora do escopo: o Sentinela **não** substitui um SIEM/IDS e não bloqueia tráfego.

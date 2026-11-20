# Política de segurança

## Versões suportadas

Correções de segurança são feitas na versão mais recente publicada.

## Como relatar uma vulnerabilidade

**Não abra issue pública.** Use o relato privado do GitHub: aba **Security** → **Report a vulnerability** neste repositório. Se não for possível, escreva para **contatopscode@gmail.com**.

Inclua, se possível:

- versão do Sentinela e sistema operacional;
- passos para reproduzir ou prova de conceito;
- impacto esperado.

O relato será confirmado em até 7 dias. A correção e a divulgação são combinadas com quem relatou, com crédito, se a pessoa quiser.

## Escopo

São especialmente relevantes:

- vazamento de segredos ou de código para fora da máquina, inclusive ao provedor de modelos;
- execução de código do repositório analisado sem `--run-tests`;
- acesso à rede sem `--network-pip-audit` ou sem o classificador remoto configurado;
- falhas no mascaramento de credenciais antes das chamadas ao modelo.

---

_English: please report vulnerabilities privately via **Security → Report a vulnerability** on this repository. Do not open public issues._

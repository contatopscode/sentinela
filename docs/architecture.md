# Arquitetura

## Fluxo

1. `collector.py` valida a raiz e lista arquivos Python (`python_files`) e JavaScript/TypeScript (`script_files`) sem escrever no repositório analisado. Diretórios excluídos são podados antes da descida, e `script_files` por ora alimenta só a varredura de segredos.
2. O orquestrador executa QA, segurança e performance em paralelo. QA permanece inativo sem `--run-tests`; `pip-audit` permanece inativo sem `--network-pip-audit`.
3. Analisadores determinísticos produzem `Finding`. Ferramentas externas ausentes viram avisos, e cada processo tem timeout.
4. O limite global de achados é aplicado. O classificador fake preserva severidade e aplica regras simples de falsos positivos.
5. A integração OpenAI, quando explicitamente selecionada, mascara e limita texto, envia o lote pela SDK oficial e valida o objeto de resposta contra `DecisionBatch`.
6. O relatório pode ser Markdown, JSON ou SARIF. Trechos de evidência não são incluídos na saída SARIF.

## Contratos

- `Finding` é produzido pelos analisadores.
- `Decision` tem severidade, falso positivo, grupo de duplicidade, confiança e estado de validação.
- `Report` combina achados, decisões, avisos e metadados da execução.
- `Classifier` recebe achados em lote e devolve decisões; explicações em texto livre não fazem parte do contrato.

Saídas de modelo precisam conter uma decisão para cada ID enviado, sem IDs repetidos. Após três respostas inválidas no total, os achados mantêm sua severidade original com confiança zero e estado não classificado.

## Guardrails

- Processos externos usam argumentos separados, sem shell, com timeout e ambiente mínimo; variáveis extras só por `SENTINELA_PASSTHROUGH_ENV`, e proxy/certificados só para `pip-audit`.
- O coletor nunca segue arquivos Python simbólicos nem varre `.git`, ambientes virtuais ou `site-packages`.
- Testes do alvo precisam de autorização explícita e devem rodar em isolamento para código não confiável.
- O acesso de rede a advisories requer `--network-pip-audit`.
- O modo fake não usa rede nem segredo.
- As chamadas ao modelo exigem escolha explícita do provedor, chave configurada, identificador de modelo e preços por token.
- O número de achados, tamanho dos trechos, lotes, tokens de saída, timeouts e tamanho do relatório têm limites configuráveis.
- O cache armazena somente decisões locais, indexadas por hash do achado mascarado, provedor e modelo.

## Limites conhecidos

A varredura local de segredos cobre padrões comuns e heurísticas de entropia, não todos os formatos possíveis. Laços aninhados são uma pista estrutural, não uma medição de desempenho. O limite de custo é estimado com preços fornecidos pelo usuário e pode divergir da cobrança efetiva. A avaliação atual é um conjunto curto e sintético.

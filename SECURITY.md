# Política de Segurança — hubsaude-cliente-csharp

## Versões suportadas

Apenas a versão **MAJOR mais recente** publicada recebe
correções de segurança. Versões anteriores são consideradas fim-de-vida
(EOL) a partir do lançamento de uma nova MAJOR.

| Versão        | Suportada |
| ------------- | --------- |
| MAJOR atual   | ✅        |
| MAJOR anterior| ❌        |

## Como reportar uma vulnerabilidade

Pedimos **divulgação responsável**. Não abra issues públicas para
vulnerabilidades de segurança. Use um dos canais abaixo.

### Canal preferencial — GitHub Security Advisories

Abra um *private security advisory* em:

<https://github.com/sesgo-ti/hubsaude-cliente-csharp/security/advisories/new>

Vantagens:
- Histórico privado, com auditoria
- Permite atribuição de CVE pelo GitHub
- Integra com o fluxo de patch

### Canal alternativo — e-mail

Caso não use o GitHub, envie para:

**kyriosdata@ufg.br**

Inclua, sempre que possível:
- Descrição do problema e impacto estimado
- Passos para reproduzir (PoC mínimo)
- Versões afetadas
- Sugestão de mitigação, se houver

## Processo de resposta

| Etapa                                 | Prazo-alvo            |
| ------------------------------------- | --------------------- |
| Acuso de recebimento                  | 3 dias úteis          |
| Avaliação inicial e classificação     | 10 dias úteis         |
| Correção em ramo privado              | conforme severidade   |
| Coordenação de divulgação             | acordada com o autor  |
| Release com correção + advisory       | conforme severidade   |

Severidade segue [CVSS v3.1](https://www.first.org/cvss/v3-1/specification-document).

## Reconhecimento

Pesquisadores que reportarem vulnerabilidades de boa-fé serão
reconhecidos publicamente no advisory, salvo solicitação explícita de
anonimato.

## Escopo

Este documento cobre o artefato publicado como
`HubSaude.Cliente` (pacote NuGet).

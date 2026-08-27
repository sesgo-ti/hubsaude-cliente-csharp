# Pol?tica de Seguran?a ? hubsaude-cliente-csharp

## Vers?es suportadas

Apenas a vers?o **MAJOR mais recente** publicada recebe
corre??es de seguran?a. Vers?es anteriores s?o consideradas fim-de-vida
(EOL) a partir do lan?amento de uma nova MAJOR.

| Vers?o        | Suportada |
| ------------- | --------- |
| MAJOR atual   | ?        |
| MAJOR anterior| ?        |

## Como reportar uma vulnerabilidade

Pedimos **divulga??o respons?vel**. N?o abra issues p?blicas para
vulnerabilidades de seguran?a. Use um dos canais abaixo.

### Canal preferencial ? GitHub Security Advisories

Abra um *private security advisory* em:

<https://github.com/sesgo-ti/hubsaude-cliente-csharp/security/advisories/new>

Vantagens:
- Hist?rico privado, com auditoria
- Permite atribui??o de CVE pelo GitHub
- Integra com o fluxo de patch

### Canal alternativo ? e-mail

Caso n?o use o GitHub, envie para:

**kyriosdata@ufg.br**

Inclua, sempre que poss?vel:
- Descri??o do problema e impacto estimado
- Passos para reproduzir (PoC m?nimo)
- Vers?es afetadas
- Sugest?o de mitiga??o, se houver

## Processo de resposta

| Etapa                                 | Prazo-alvo            |
| ------------------------------------- | --------------------- |
| Acuso de recebimento                  | 3 dias ?teis          |
| Avalia??o inicial e classifica??o     | 10 dias ?teis         |
| Corre??o em ramo privado              | conforme severidade   |
| Coordena??o de divulga??o             | acordada com o autor  |
| Release com corre??o + advisory       | conforme severidade   |

Severidade segue [CVSS v3.1](https://www.first.org/cvss/v3-1/specification-document).

## Reconhecimento

Pesquisadores que reportarem vulnerabilidades de boa-f? ser?o
reconhecidos publicamente no advisory, salvo solicita??o expl?cita de
anonimato.

## Escopo

Este documento cobre o artefato publicado como
`HubSaude.Cliente` (pacote NuGet).

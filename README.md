# hubsaude-cliente-csharp

[![Version](https://img.shields.io/badge/Version-0.1.0-yellow)]()
[![.NET 10](https://img.shields.io/badge/.NET-10.0-blue)]()
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Cliente C#/.NET para obtenção de tokens de acesso ao HubSaúde via
[SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
(SMART-on-FHIR). Encapsula a montagem do JWT *client assertion*, sua
assinatura e a troca pelo *access token* no endpoint OAuth 2.0.

O contrato comportamental está em [`ESPECIFICACAO.md`](ESPECIFICACAO.md)
— requisitos normativos que refletem esta implementação e servem de
referência para o portfólio oficial de SDKs: Java, TypeScript/Node.js
(consumível também por JavaScript), C#/.NET e Python.

## Dependência NuGet

<!-- Definir quando o pacote NuGet for publicado. -->

## Política da API pública

Enquanto a biblioteca estiver na série `0.x`, sua API é provisória:
versões `MINOR` podem introduzir mudanças incompatíveis e versões `PATCH`
preservam compatibilidade. A partir de `1.0.0`, a evolução seguirá
estritamente o
[Versionamento Semântico 2.0.0](https://semver.org/lang/pt-BR/).

<!-- Definir detalhes da API pública C#/.NET. -->

## Uso básico

<!-- Definir após a implementação da API pública. -->

## Ciclo de vida, cache e erros

<!-- Definir após a implementação da API pública. -->

## Fontes de chave (`ISigningStrategy`)

A escolha de *onde* a chave privada reside é a decisão arquitetural
mais relevante para uma integração de produção:

| Fonte | Quando usar | Exposição da chave |
|-------|-------------|--------------------|
| PEM (PKCS#8) | Prototipação e testes | Arquivo em claro no disco |
| PEM com senha | Mitigação adicional quando PEM é inevitável | Cifrada em disco; senha em runtime |
| PKCS#12 direto | **Recomendado para produção** com chaves em software | Permanece dentro do armazenamento de certificados |
| HSM via PKCS#11 | Produção com chave não-exportável | Nunca sai do hardware |
| OpenBao (cofre) | Chave provisionada por cofre central | Buscada em runtime; nunca em disco |

### Tamanho mínimo de chave

Chaves fracas são rejeitadas no carregamento e na construção da
estratégia de assinatura (fail-fast), conforme NIST SP 800-57:

| Algoritmo | Mínimo aceito |
|-----------|---------------|
| RSA | 2048 bits (módulo) |
| EC | P-256 (campo de 256 bits) |

Handles PKCS#11 opacos que não expõem os parâmetros da chave não são
validados (a política de tamanho fica a cargo do HSM).

### PKCS#12 direto

<!-- Definir API C#/.NET. -->

### HSM via PKCS#11

<!-- Definir API C#/.NET. -->

### OpenBao / chave já carregada

<!-- Definir API C#/.NET. -->

### PEM com senha

<!-- Definir API C#/.NET. -->

## Configuração avançada

<!-- Definir API C#/.NET. -->

O endpoint deve usar `https`; o esquema `http` é aceito apenas para
`localhost`/`127.0.0.1` (desenvolvimento e testes locais).

Valores menores ou iguais a zero em `assertionTtlSeconds`, `maxRetries`
e `tokenCacheMarginSeconds` são substituídos pelos padrões de 60 s, 3
tentativas totais e 30 s, respectivamente. `tokenCacheMaxEntries` deve
ser positivo; valor inválido faz a construção do cliente falhar.

### Contexto de Guia de Implementação (`hub_ctx`)

O claim proprietário `hub_ctx` declara o Guia de Implementação (IG) e a
versão pretendidos na sessão. Configure conforme definido na
`ESPECIFICACAO.md`.

### Identificador de chave (`kid`)

Quando o servidor de autorização publica múltiplas chaves (JWKS), use
`keyId` para incluir o header `kid` no *client assertion*, permitindo que
o servidor selecione a chave pública correta para validar a assinatura.

### Descoberta automática do endpoint

Em vez de fixar `tokenEndpoint`, informe a base FHIR — o cliente resolve
via `.well-known/smart-configuration`.

### `serverTrustAnchor` — quando usar

Em produção o HubSaúde usa CA já presente no trust store padrão do .NET.
Use uma autoridade de certificação customizada apenas em testes locais,
homologação com CA interna ou desenvolvimento com certificados ad hoc.

## Preparação de certificados PFX/P12 → PEM

<!-- Definir instruções específicas para C#/.NET. -->

## Resiliência em produção

A especificação prevê cache de token e *retries* com *backoff*
exponencial. Na série `0.1.x`, apenas `RetryPolicy`, `FaultToleranceConfig`
e os defaults normativos de `SmartTokenClient` estão implementados; cache,
laço de retry HTTP e `ObtainTokenAsync` ainda estão pendentes. Para
proteção adicional contra falhas prolongadas do AS, combine com um
*circuit breaker* externo na camada de orquestração.

## Correlação e observabilidade (`traceparent`)

O HubSaúde ignora headers como `X-Correlation-Id` enviados pelo
cliente: a correlação é derivada exclusivamente do contexto de
trace W3C ([W3C Trace Context](https://www.w3.org/TR/trace-context/)).

A geração de IDs W3C (`TraceContext`) já está implementada. A inclusão
automática do header `traceparent` em requisições HTTP (token endpoint e
descoberta via `.well-known/smart-configuration`) será adicionada com o
fluxo de obtenção de token.

## Troubleshooting

| Erro | Causa provável | Solução |
|------|----------------|---------|
| | | |

## Build e testes

```bash
dotnet restore
dotnet build
dotnet test
```

# hubsaude-cliente-csharp

[![Version](https://img.shields.io/badge/Version-0.1.0-yellow)]()
[![.NET 8](https://img.shields.io/badge/.NET-10.0-blue)]()
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Cliente C#/.NET para obten��o de tokens de acesso ao HubSa�de via
[SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
(SMART-on-FHIR). Encapsula a montagem do JWT *client assertion*, sua
assinatura e a troca pelo *access token* no endpoint OAuth 2.0.

O contrato comportamental est� em [`ESPECIFICACAO.md`](ESPECIFICACAO.md)
� requisitos normativos que refletem esta implementa��o e servem de
refer�ncia para o portf�lio oficial de SDKs: Java, TypeScript/Node.js
(consum�vel tamb�m por JavaScript), C#/.NET e Python.

## Depend�ncia NuGet

<!-- Definir quando o pacote NuGet for publicado. -->

## Pol�tica da API p�blica

Enquanto a biblioteca estiver na s�rie `0.x`, sua API � provis�ria:
vers�es `MINOR` podem introduzir mudan�as incompat�veis e vers�es `PATCH`
preservam compatibilidade. A partir de `1.0.0`, a evolu��o seguir�
estritamente o
[Versionamento Sem�ntico 2.0.0](https://semver.org/lang/pt-BR/).

<!-- Definir detalhes da API p�blica C#/.NET. -->

## Uso b�sico

<!-- Definir ap�s a implementa��o da API p�blica. -->

## Ciclo de vida, cache e erros

<!-- Definir ap�s a implementa��o da API p�blica. -->

## Fontes de chave (`SigningStrategy`)

A escolha de *onde* a chave privada reside � a decis�o arquitetural
mais relevante para uma integra��o de produ��o:

| Fonte | Quando usar | Exposi��o da chave |
|-------|-------------|--------------------|
| PEM (PKCS#8) | Prototipa��o e testes | Arquivo em claro no disco |
| PEM com senha | Mitiga��o adicional quando PEM � inevit�vel | Cifrada em disco; senha em runtime |
| PKCS#12 direto | **Recomendado para produ��o** com chaves em software | Permanece dentro do armazenamento de certificados |
| HSM via PKCS#11 | Produ��o com chave n�o-export�vel | Nunca sai do hardware |
| OpenBao (cofre) | Chave provisionada por cofre central | Buscada em runtime; nunca em disco |

### Tamanho m�nimo de chave

Chaves fracas s�o rejeitadas no carregamento e na constru��o da
estrat�gia de assinatura (fail-fast), conforme NIST SP 800-57:

| Algoritmo | M�nimo aceito |
|-----------|---------------|
| RSA | 2048 bits (m�dulo) |
| EC | P-256 (campo de 256 bits) |

Handles PKCS#11 opacos que n�o exp�em os par�metros da chave n�o s�o
validados (a pol�tica de tamanho fica a cargo do HSM).

### PKCS#12 direto

<!-- Definir API C#/.NET. -->

### HSM via PKCS#11

<!-- Definir API C#/.NET. -->

### OpenBao / chave j� carregada

<!-- Definir API C#/.NET. -->

### PEM com senha

<!-- Definir API C#/.NET. -->

## Configura��o avan�ada

<!-- Definir API C#/.NET. -->

O endpoint deve usar `https`; o esquema `http` � aceito apenas para
`localhost`/`127.0.0.1` (desenvolvimento e testes locais).

Valores menores ou iguais a zero em `assertionTtlSeconds`, `maxRetries`
e `tokenCacheMarginSeconds` s�o substitu�dos pelos padr�es de 60 s, 3
tentativas totais e 30 s, respectivamente. `tokenCacheMaxEntries` deve
ser positivo; valor inv�lido faz a constru��o do cliente falhar.

### Contexto de Guia de Implementa��o (`hub_ctx`)

O claim propriet�rio `hub_ctx` declara o Guia de Implementa��o (IG) e a
vers�o pretendidos na sess�o. Configure conforme definido na
`ESPECIFICACAO.md`.

### Identificador de chave (`kid`)

Quando o servidor de autoriza��o publica m�ltiplas chaves (JWKS), use
`keyId` para incluir o header `kid` no *client assertion*, permitindo que
o servidor selecione a chave p�blica correta para validar a assinatura.

### Descoberta autom�tica do endpoint

Em vez de fixar `tokenEndpoint`, informe a base FHIR � o cliente resolve
via `.well-known/smart-configuration`.

### `serverTrustAnchor` � quando usar

Em produ��o o HubSa�de usa CA j� presente no trust store padr�o do .NET.
Use uma autoridade de certifica��o customizada apenas em testes locais,
homologa��o com CA interna ou desenvolvimento com certificados ad hoc.

## Prepara��o de certificados PFX/P12 ? PEM

<!-- Definir instru��es espec�ficas para C#/.NET. -->

## Resili�ncia em produ��o

A biblioteca j� cobre cache de token + *retries* com *backoff*. Para
prote��o adicional contra falhas prolongadas do AS, combine com um
*circuit breaker* externo na camada de orquestra��o.

## Correla��o e observabilidade (`traceparent`)

O HubSa�de ignora headers como `X-Correlation-Id` enviados pelo
cliente: a correla��o � derivada exclusivamente do contexto de
trace W3C ([W3C Trace Context](https://www.w3.org/TR/trace-context/)).

Por isso, toda requisi��o HTTP desta biblioteca (token endpoint e
descoberta via `.well-known/smart-configuration`) envia o header
`traceparent` conforme definido na especifica��o.

## Troubleshooting

| Erro | Causa prov�vel | Solu��o |
|------|----------------|---------|
| | | |

## Build e testes

```bash
dotnet restore
dotnet build
dotnet test
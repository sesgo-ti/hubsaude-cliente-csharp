# hubsaude-cliente-csharp

[![Version](https://img.shields.io/badge/Version-0.4.1-yellow)]()
[![.NET 10](https://img.shields.io/badge/.NET-10.0-blue)]()
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Cliente C#/.NET para obtenção de tokens de acesso ao HubSaúde via
[SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
(SMART-on-FHIR). Encapsula a montagem do JWT *client assertion*, sua
assinatura e a troca pelo *access token* no endpoint OAuth 2.0.

O contrato comportamental está em [`ESPECIFICACAO.md`](ESPECIFICACAO.md):
requisitos funcionais e não funcionais desta biblioteca. Em caso de
divergência aparente entre o README e a especificação, a especificação
prevalece.

## Dependência NuGet

O identificador do pacote é **`HubSaude.Cliente`** (versão atual
`0.4.1`). O nupkg (e o SBOM CycloneDX) saem da GitHub Release gerada
pelo workflow de tag; a publicação no nuget.org ainda não faz parte
deste repositório.

```xml
<PackageReference Include="HubSaude.Cliente" Version="0.4.1" />
```

## Política da API pública

Enquanto a biblioteca estiver na série `0.x`, sua API é provisória:
versões `MINOR` podem introduzir mudanças incompatíveis e versões `PATCH`
preservam compatibilidade. A partir de `1.0.0`, a evolução seguirá
estritamente o
[Versionamento Semântico 2.0.0](https://semver.org/lang/pt-BR/).

Todos os tipos e membros `public` no namespace `HubSaude.Cliente`
integram a API pública. Membros `internal` podem mudar sem aviso. A
criação de `SmartTokenClient` é feita **exclusivamente** por
`SmartTokenClient.CreateBuilder()`; a classe não expõe construtores
públicos.

Algoritmos de assinatura na fachada pública são os identificadores JWT
(RFC 7518): `RS384`, `ES256`, `PS256`, etc.
`SigningStrategyFactory.NormalizeJwtAlgorithm` valida e normaliza o
`alg`. `JwtAlgorithmToJava` e `PssParameterSpecFor` permanecem apenas
como aliases obsoletos. Mensagens de erro falam em PKCS#12 e PEM, não
em termos de outro ecossistema.

## Uso básico

```csharp
await using var client = SmartTokenClient.CreateBuilder()
    .TokenEndpoint("https://hub.saude.go.gov.br/auth/token")
    .ClientId("meu-sistema")
    .PrivateKeyPem("chave-privada.pem")
    .CertificatePem("certificado.pem")
    .Build();

string token = await client.ObtainTokenAsync("system/Patient.rs");
```

A instância é **task-safe**, mantém cache do token (renovado conforme
margem de expiração) e executa *retries* com *backoff* exponencial
assíncrono. Reutilize a mesma instância pelo ciclo de vida da aplicação
e invoque `Dispose`/`DisposeAsync` uma única vez no encerramento.

## Ciclo de vida, cache e erros

`SmartTokenClient` implementa `IDisposable` e `IAsyncDisposable`. O
fechamento é idempotente, aguarda operações em voo, encerra o
`HttpClient` interno e invalida todo o cache. Após o fechamento, novas
obtenções de token falham com `ObjectDisposedException`.

As operações de token podem propagar:

| Tipo | Situação |
|------|----------|
| `HttpRequestException` / `IOException` | Falha de rede não recuperada pelos retries internos |
| `OperationCanceledException` | Cancelamento da tarefa ou timeout HTTP |
| `SmartTokenException` | Configuração criptográfica inválida, resposta HTTP/JSON inválida ou algoritmo não suportado |
| `SigningException` | Falha da estratégia criptográfica ao assinar o `client_assertion` |

Após receber `401` ao usar um token em um endpoint FHIR, invalide a
entrada antes de obter um novo token:

```csharp
client.InvalidateCache("system/Patient.rs");
string renewedToken = await client.ObtainTokenAsync("system/Patient.rs");
```

Não repita indefinidamente após um novo `401`. Consulte
[`docs/integracao-enterprise.md`](docs/integracao-enterprise.md) e
[`docs/troubleshooting.md`](docs/troubleshooting.md).

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

```csharp
await using var client = SmartTokenClient.CreateBuilder()
    .TokenEndpoint("https://hub.saude.go.gov.br/auth/token")
    .ClientId("meu-sistema")
    .ClientPkcs12("certificado.pfx", "alias-da-chave", "senha-pfx".ToCharArray())
    .Build();
```

O PKCS#12 fornece a chave para o JWT e o certificado para mTLS. A senha
é zerada ao final de `Build`. No Windows o SDK importa o PFX com
`UserKeySet|Exportable` (o Schannel rejeita chave efêmera —
`0x8009030D`). Nos demais sistemas usa `EphemeralKeySet`.

Não carregue o PFX manualmente com `X509KeyStorageFlags.EphemeralKeySet`
e `ClientCertificate` no Windows para mTLS. Prefira `ClientPkcs12`, ou
combine `SigningStrategy` (HSM) com `ClientPkcs12` só para o certificado
de cliente.

Alternativa já carregada em memória (fora do Windows, ou quando a chave
já está no store do usuário):

```csharp
var pfx = X509CertificateLoader.LoadPkcs12FromFile(
    "certificado.pfx",
    "senha-pfx",
    OperatingSystem.IsWindows()
        ? X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
        : X509KeyStorageFlags.EphemeralKeySet);
await using var client = SmartTokenClient.CreateBuilder()
    .TokenEndpoint("https://hub.saude.go.gov.br/auth/token")
    .ClientId("meu-sistema")
    .SigningStrategy(SigningStrategyFactory.FromCertificate(pfx))
    .ClientCertificate(pfx)
    .Build();
```

### HSM via PKCS#11

A chave privada permanece no token. O cliente fecha a sessão PKCS#11
no `Dispose`. Para mTLS, combine com um PFX que contenha só o
certificado de cliente (ou um `X509Certificate2` com chave não-exportável):

```csharp
await using var client = SmartTokenClient.CreateBuilder()
    .TokenEndpoint("https://hub.saude.go.gov.br/auth/token")
    .ClientId("meu-sistema")
    .SigningStrategy(SigningStrategyFactory.FromPkcs11(new Pkcs11Options
    {
        Library = "/usr/lib/softhsm/libsofthsm2.so",
        Pin = pinDoToken,
        TokenLabel = "hubsaude",
        KeyLabel = "jwt-key",
        JwtAlgorithm = "RS384",
    }))
    .ClientPkcs12("cliente-mtls.pfx", "alias-do-cert", senhaPfx)
    .Build();
```

`Library` é o módulo do fabricante (`.so` / `.dll` / `.dylib`). Informe
`KeyLabel` e/ou `KeyId`, e no máximo um entre `Slot` e `TokenLabel`.
O PIN é `string` (limitação de `C_Login`). PEM e PKCS#11 são
mutuamente exclusivos para a *assinatura*.

### OpenBao / chave já carregada

```csharp
RSA chave = /* obtida do cofre */;
await using var client = SmartTokenClient.CreateBuilder()
    .TokenEndpoint("https://hub.saude.go.gov.br/auth/token")
    .ClientId("meu-sistema")
    .SigningStrategy(SigningStrategyFactory.FromPrivateKeyForJwt(chave, "RS384"))
    .Build();
```

### PEM com senha

```csharp
var senha = "segredo".ToCharArray();
await using var client = SmartTokenClient.CreateBuilder()
    .TokenEndpoint("https://hub.saude.go.gov.br/auth/token")
    .ClientId("meu-sistema")
    .PrivateKeyPem("chave-privada.pem")
    .PrivateKeyPassword(senha)
    .Build();
```

## Configuração avançada

```csharp
await using var client = SmartTokenClient.CreateBuilder()
    .TokenEndpoint("https://hub.saude.go.gov.br/auth/token")
    .ClientId("meu-sistema")
    .PrivateKeyPem("chave-privada.pem")
    .CertificatePem("certificado.pem")
    .ServerTrustAnchor("ca-custom.pem")  // simulador/homologação
    .TlsProtocol("TLSv1.2")              // homologação HubSaúde: TLSv1.2; padrão do SDK: TLSv1.3
    .ConnectTimeout(TimeSpan.FromSeconds(10))
    .RequestTimeout(TimeSpan.FromSeconds(30))
    .AssertionTtlSeconds(120)
    .EnableTokenCache(true)
    .TokenCacheMarginSeconds(30)
    .TokenCacheMaxEntries(1_000)
    .MaxRetries(3)
    .JwtAlgorithm("RS384")
    .KeyId("minha-chave-2026")
    .HubContext("hemograma", "0.0.1")
    .Logger(logger) // ILogger opcional
    .Build();
```

O endpoint deve usar `https`; o esquema `http` é aceito apenas para
`localhost`/`127.0.0.1` (desenvolvimento e testes locais).

Valores menores ou iguais a zero em `AssertionTtlSeconds`, `MaxRetries`
e `TokenCacheMarginSeconds` são substituídos pelos padrões de 60 s, 3
tentativas totais e 30 s, respectivamente. `TokenCacheMaxEntries` deve
ser positivo; valor inválido faz `Build` falhar.

### Contexto de Guia de Implementação (`hub_ctx`)

O claim proprietário `hub_ctx` declara o Guia de Implementação (IG) e a
versão pretendidos na sessão. Configure com `HubContext(ig, versao)`: o
`ig` usa minúsculas, dígitos e hífen (ex.: `hemograma`) e a `versao` é
SemVer completo `MAJOR.MINOR.PATCH` (ex.: `0.0.1`). Quando não
configurado, o claim é omitido — servidores que o exigem rejeitarão o
assertion.

### Identificador de chave (`kid`)

Quando o servidor de autorização publica múltiplas chaves (JWKS), use
`KeyId("...")` para incluir o header `kid` no *client assertion*,
permitindo que o servidor selecione a chave pública correta para
validar a assinatura. Se não configurado, o header contém apenas
`alg` e `typ`.

### Descoberta automática do endpoint

Em vez de fixar `TokenEndpoint`, informe a base FHIR — o cliente
resolve via `.well-known/smart-configuration`:

```csharp
.FhirBase("https://hub.saude.go.gov.br")
```

`TokenEndpoint` e `FhirBase` são mutuamente exclusivos.

### `ServerTrustAnchor` — quando usar

Em produção o HubSaúde usa CA já presente no trust store padrão do .NET.
Use `ServerTrustAnchor` apenas em testes locais com o simulador,
homologação com CA interna, ou desenvolvimento com certificados ad hoc.
Não desabilite a validação de certificado do servidor em produção.

## Preparação de certificados PFX/P12 → PEM

Útil quando a chave precisa ser materializada em PEM. Se você usa
PKCS#12 direto (`ClientPkcs12`) ou HSM, ignore esta seção. No .NET 10
prefira `X509CertificateLoader.LoadPkcs12FromFile` quando o material
já estiver em PFX; o OpenSSL abaixo gera PEM para `PrivateKeyPem` /
`CertificatePem`.

```bash
# Chave privada (atenção: -nodes salva em claro)
openssl pkcs12 -in certificado.pfx -nocerts -nodes -out chave-privada.pem

# Certificado público
openssl pkcs12 -in certificado.pfx -clcerts -nokeys -out certificado.pem

# (Opcional) Forçar PKCS#8
openssl pkcs8 -topk8 -nocrypt -in chave-privada.pem -out chave-pkcs8.pem

# (Opcional) Cifrar a chave em AES-256
openssl pkcs8 -topk8 -v2 aes-256-cbc -in chave-privada.pem -out chave-encrypted.pem
```

## Resiliência em produção

A biblioteca já cobre cache de token + *retries* com *backoff*. Para
proteção adicional contra falhas prolongadas do AS, combine com um
*circuit breaker* externo na camada de orquestração. O
[guia de integração enterprise](docs/integracao-enterprise.md) descreve
ownership, composição de resiliência e métricas sem acoplar o SDK a um
framework.

`ObtainTokenAsync` / `ObtainTokenResponseAsync` usam cache LRU por
scope, *single-flight* assíncrono e retry apenas para falhas
transitórias de rede (timeout e conexão). HTTP 429 e demais status não
sofrem retry automático.

## Correlação e observabilidade (`traceparent`)

O HubSaúde ignora headers como `X-Correlation-Id` enviados pelo
cliente: a correlação é derivada **exclusivamente** do contexto de
trace W3C ([W3C Trace Context](https://www.w3.org/TR/trace-context/)).
Por isso, toda requisição HTTP desta biblioteca (token endpoint e
descoberta via `.well-known/smart-configuration`) envia o header
`traceparent` no formato `00-<trace-id>-<parent-id>-00`, com IDs
gerados por tentativa — cada retry carrega um par novo. Não há
dependência do SDK OpenTelemetry.

A flag `sampled` é `00` (*not sampled*): a biblioteca não grava spans.

**Como usar com o suporte**: em falhas, o trace-id enviado aparece nas
mensagens de `SmartTokenException` (`traceId=...`). Informe esse valor
ao suporte do HubSaúde para correlacionar o integrador com a
plataforma.

Aplicações instrumentadas com o OpenTelemetry .NET podem substituir o
header no `HttpClient` pelo contexto do span ativo; o trace-id efetivo
passa a ser o da instrumentação.

## Troubleshooting

| Erro | Causa provável | Solução |
|------|----------------|---------|
| `SmartTokenException` HTTP 401 | Assertion rejeitado (`kid`, `hub_ctx`, chave) | Confira `clientId`, `KeyId` e o par chave/certificado |
| `SmartTokenException` HTTP 429 | Rate limit do AS | Respeite `Retry-After`; o SDK não retenta sozinho |
| PEM/PKCS#8 não reconhecido | Chave em PKCS#1 ou formato inesperado | Converta com `openssl pkcs8 -topk8` ou use PKCS#12 |
| TLS / confiança da CA | CA do servidor não no trust store | Use `ServerTrustAnchor` (simulador/homologação) — ver [troubleshooting TLS](docs/troubleshooting.md) |
| Assinatura / par inconsistente | Certificado não corresponde à chave | Compare *modulus* (OpenSSL) ou use o mesmo PFX em `ClientPkcs12` |
| TLS abortado após mTLS | Certificado de cliente rejeitado, ou Schannel sem chave persistida | Verifique validade/revogação; no Windows use `ClientPkcs12` (não `EphemeralKeySet`) |
| Handshake TLS 1.3 falha no homolog | Ambiente exige TLS 1.2 | `.TlsProtocol("TLSv1.2")` |
| `ObjectDisposedException` | Cliente já encerrado | Não reutilize após `Dispose` |

Para diagnóstico aprofundado de confiança SSL/TLS, consulte o
[guia de troubleshooting TLS](docs/troubleshooting.md).

## Build e testes

```bash
dotnet restore
dotnet build HubSaude.Cliente.sln --configuration Release
dotnet test HubSaude.Cliente.sln --configuration Release
```

O projeto de testes aplica Coverlet (mínimo 85% de line coverage) e
testes de arquitetura em `tests/HubSaude.Cliente.Tests/ArchRules/`.
O CI Linux instala SoftHSM2 e executa os testes PKCS#11 de ponta a
ponta. Sem o módulo, esses casos são omitidos (a suíte unitária não
depende de HSM). `Pkcs11SigningStrategy` fica fora do gate Coverlet
porque exige biblioteca nativa.

### Smoke contra homologação (integrador)

`tools/HubSaude.Smoke` **não** entra no `HubSaude.Cliente.sln` nem no
CI: é um console opt-in contra o ambiente real. Nenhuma credencial
fica neste repositório (`.env` está no `.gitignore`).

| Variável | Obrigatória | Descrição |
|----------|-------------|-----------|
| `HOMOLOG_CLIENT_ID` | sim | `client_id` já registrado no homolog |
| `HOMOLOG_PFX_PATH` + `HOMOLOG_PFX_ALIAS` + `HOMOLOG_PFX_PASSWORD` | um dos conjuntos | PKCS#12 (recomendado no Windows) |
| `HOMOLOG_CERT_PATH` + `HOMOLOG_KEY_PATH` | o outro conjunto | PEM; o SDK materializa PKCS#12 para mTLS |
| `HOMOLOG_FHIR_BASE` | não | Padrão: `https://hub-homolog.saude.go.gov.br/` |
| `HOMOLOG_SCOPE` | não | Padrão: `system/Patient.rs` |
| `HOMOLOG_IG` / `HOMOLOG_IG_VERSAO` | não | Padrão: `hemograma` / `0.0.1` |

O smoke usa **TLS 1.2** (o homolog recusa TLS 1.3 no handshake).

```bash
# PowerShell
$env:HOMOLOG_CLIENT_ID = "org:..."
$env:HOMOLOG_CERT_PATH = "C:\certs\cliente.cer"
$env:HOMOLOG_KEY_PATH  = "C:\certs\cliente.key"
dotnet run --project tools/HubSaude.Smoke
```

Sem as variáveis obrigatórias o processo encerra com código 2 e a
lista acima. Código 1 indica falha na obtenção do token.

## Publicação de nova versão (release)

O workflow [`release.yml`](.github/workflows/release.yml) é disparado por tag
no padrão `v<MAJOR>.<MINOR>.<PATCH>`:

```bash
git tag -a v0.3.1 -m "hubsaude-cliente-csharp 0.3.1"
git push origin v0.3.1
```

O workflow deriva a versão da tag, executa `dotnet test` em Release e
publica `nupkg`, `snupkg` e SBOM CycloneDX na GitHub Release.

## Referências

| Especificação | Descrição |
|---------------|-----------|
| [SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html) | Perfil HL7 FHIR para autenticação backend-to-backend |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) | OAuth 2.0 (`client_credentials`) |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) | JSON Web Token (JWT) |
| [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) / [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | Assertion Framework e JWT Bearer Assertion |

O [guia de integração enterprise](docs/integracao-enterprise.md)
complementa essas referências com lifecycle, resiliência, métricas e
integração com DI.

## Licença e contribuição

Apache License 2.0 — ver [`LICENSE`](LICENSE) e [`NOTICE`](NOTICE).
Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — fluxo e DCO
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1
- [`SECURITY.md`](SECURITY.md) — divulgação responsável de vulnerabilidades

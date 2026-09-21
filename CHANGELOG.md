# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

## [0.4.1] - 2026-09-10

Fachada pública alinhada a convenções .NET/JWT: mensagens, XML docs e
nomes de algoritmo sem jargão Java.

### Adicionado

- `SigningStrategyFactory.NormalizeJwtAlgorithm`: valida e devolve o
  `alg` JWT canônico (`RS384`, `ES256`, …).
- `SigningStrategyFactory.PssParametersFor`: parâmetros PSS (RFC 7518
  §3.5) sem o sufixo Java `ParameterSpec`.
- `PrivateKeySigningStrategy` aceita identificadores JWT (`RS*`, `PS*`,
  `ES*`) além dos identificadores de assinatura legados.

### Alterado

- Mensagens de erro de PKCS#12 e PEM: `PKCS#12` no lugar de `KeyStore`;
  formato de chave sem referência a `PemObject`.
- XML da API pública: `<param>`, `<returns>` e `<exception>` (incluindo
  `ArgumentNullException`) nos membros que o consumidor vê no
  IntelliSense.
- `JwtAlgorithmToJava` e `PssParameterSpecFor` marcados `[Obsolete]`;
  o mapeamento legado permanece para código existente.

## [0.4.0] - 2026-09-09

Assinatura em HSM (PKCS#11), mTLS compatível com Schannel no Windows e
ferramenta opt-in de smoke contra homologação.

### Adicionado

- **PKCS#11** via `SigningStrategyFactory.FromPkcs11` e `Pkcs11Options`
  (`Pkcs11SigningStrategy`, Pkcs11Interop). A chave privada não sai do
  token; `SmartTokenClient.Dispose` encerra a sessão PKCS#11 quando a
  estratégia implementa `IDisposable`.
- Composição **`SigningStrategy` + `ClientPkcs12`**: JWT assinado no HSM
  (ou cofre) e mTLS com certificado em PFX separado.
- Smoke opt-in de homologação em `tools/HubSaude.Smoke` (variáveis
  `HOMOLOG_*`; fora do `HubSaude.Cliente.sln` e do CI).
- Testes PKCS#11 de ponta a ponta com SoftHSM2 no CI/release Linux
  (`SOFTHSM_LIB`).

### Alterado

- **PKCS#12 / mTLS**: no Windows a chave é importada com
  `UserKeySet|Exportable`; par PEM+certificado é materializado em PKCS#12
  antes do handshake (`EphemeralKeySet` permanece nos demais SOs).
- `ESPECIFICACAO.md`, README, guias de integração e troubleshooting
  alinhados a PKCS#11 nativo e ao fluxo Schannel no Windows.
- `NOTICE`: atribuição Pkcs11Interop (Apache-2.0).

### Corrigido

- mTLS no Windows com `PrivateKeyPem` + `CertificatePem` (Schannel
  rejeitava chave efêmera — `0x8009030D`).
- PKCS#11 no Ubuntu 24+: Pkcs11Interop carrega `libdl`; o SDK mapeia
  para `libdl.so.2` (sem o symlink `libdl.so` o módulo não abria).

## [0.3.0] - 2026-09-01

Fluxo completo de obtenção de token no .NET: HTTP, cache, retry, TLS/mTLS
e descoberta SMART, alinhados à `ESPECIFICACAO.md`.

### Adicionado

- `ObtainTokenAsync` / `ObtainTokenResponseAsync`, `TokenResponse`,
  invalidação de cache e `traceparent` em cada requisição HTTP.
- Cache LRU por scope com single-flight (`SemaphoreSlim`, 32 stripes) e
  retry com backoff exponencial assíncrono (somente falhas transitórias).
- Tratamento HTTP 200/`expires_in`, 429 sem retry, sanitização de corpos
  de erro e heurística de rejeição mTLS.
- **PKCS#12** via `ClientPkcs12` (assinatura + mTLS) e
  `FromPkcs12`/`FromPkcs12File`.

## [0.2.0] - 2026-08-27

Primeira release com código da biblioteca. O fluxo completo de obtenção de
token (`ObtainTokenAsync`, JWT, HTTP, cache e descoberta de endpoint) ainda
está pendente; esta versão entrega a fundação normativa, material
criptográfico e resiliência parcial alinhados à `ESPECIFICACAO.md`.

### Adicionado

- Biblioteca **`HubSaude.Cliente`** (.NET 10): `SmartTokenClient` com
  constantes normativas (timeouts, TTL, retries, cache, TLS, algoritmo JWT),
  ciclo de vida thread-safe (`IDisposable`/`IAsyncDisposable`) e entrada pública
  exclusiva via `SmartTokenClient.CreateBuilder()`.
- **`SmartTokenClientBuilder`** (esqueleto), **`FaultToleranceConfig`** e
  **`RetryPolicy`** (backoff exponencial sem jitter, RF-07.4).
- **`TraceContext`**: geração de `traceparent` W3C por requisição (RF-02.4).
- **`ISigningStrategy`**, **`PrivateKeySigningStrategy`** e
  **`SigningStrategyFactory`** (RF-12, RF-16): assinatura RSA/ECDSA com
  mapeamento JWT→algoritmo de assinatura, suporte a RS\*/PS\*/ES\* e
  parâmetros PSS (RFC 7518 §3.5).
- **`PemLoader`** (RF-12/13): carregamento de chaves PEM (PKCS#8, PKCS#1 RSA,
  criptografadas PKCS#8 e OpenSSL tradicional via BouncyCastle), certificados
  X.509, validação fail-fast de tamanho mínimo (RSA ≥ 2048 bits, EC ≥ P-256)
  e zeragem de senha/material sensível (RNF-03).
- **`CertificateValidator`** (RF-14): parse e validação de período de
  validade de certificados PEM.
- **`KeyCertificateConsistency`** (RF-15): verificação de par chave/certificado
  com desafio fixo (`key-pair-consistency-check`).
- **`SmartTokenException`** e **`SigningException`** (RF-19).
- Suíte de testes xUnit com **128 casos** e gate **Coverlet** de 85% de line
  coverage (RNF-06).
- Infraestrutura de build: `Directory.Build.props` (`TreatWarningsAsErrors`,
  `EnforceCodeStyleInBuild`), `global.json` (SDK 10.0.400), `.editorconfig`.
- Workflow **CI** (GitHub Actions): `dotnet test` em Release, cache NuGet, SDK
  pinado, publicação de artefatos TRX e Cobertura.
- **`ESPECIFICACAO.md`**: coluna de rastreabilidade C# (§10); documentação de
  repositório revisada (`README`, `CONTRIBUTING`, `SECURITY`, `CODE_OF_CONDUCT`).

### Alterado

- **`README.md`**: encoding UTF-8, badge .NET 10, estado real da implementação
  parcial (resiliência e `traceparent` descritos com precisão).

## [0.1.0] - 2026-08-17

### Adicionado

- Arquivos `.md` iniciais e estrutura base do repositório.

---

## Convenções de Versionamento

- **MAJOR**: Mudanças incompatíveis na API pública
- **MINOR**: Novas funcionalidades compatíveis com versões anteriores
- **PATCH**: Correções de bugs compatíveis com versões anteriores

Durante a série **`0.x`**, versões **MINOR** podem introduzir mudanças
incompatíveis; versões **PATCH** preservam compatibilidade.

## Links

- [Repositório](https://github.com/sesgo-ti/hubsaude-cliente-csharp)
- [Documentação SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
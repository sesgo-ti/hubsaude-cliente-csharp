# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

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
  mapeamento JWT→JCA, suporte a RS\*/PS\*/ES\* e parâmetros PSS (RFC 7518 §3.5).
- **`PemLoader`** (RF-12/13): carregamento de chaves PEM (PKCS#8, PKCS#1 RSA,
  criptografadas PKCS#8 e OpenSSL tradicional via BouncyCastle), certificados
  X.509, validação fail-fast de tamanho mínimo (RSA ≥ 2048 bits, EC ≥ P-256)
  e zeragem de senha/material sensível (RNF-03).
- **`CertificateValidator`** (RF-14): parse e validação de período de
  validade de certificados PEM.
- **`KeyCertificateConsistency`** (RF-15): verificação de par chave/certificado
  com desafio fixo compatível com a implementação Java.
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
- [Repositório Origem](https://github.com/sesgo-ti/hubsaude-cliente-java)
- [Documentação SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
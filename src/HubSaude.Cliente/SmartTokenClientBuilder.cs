// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace HubSaude.Cliente;

/// <summary>
/// Builder fluente para <see cref="SmartTokenClient"/> (RF-18).
/// </summary>
public sealed class SmartTokenClientBuilder
{
    private string? _tokenEndpoint;
    private string? _discoveryBaseUrl;
    private string? _clientId;
    private string? _hubCtxIg;
    private string? _hubCtxVersao;
    private readonly SigningSettings _signing = new();
    private readonly TlsSettings _tls = new();
    private FaultToleranceConfig _faultToleranceConfig = new(
        SmartTokenClient.DefaultConnectTimeout,
        SmartTokenClient.DefaultRequestTimeout,
        SmartTokenClient.DefaultAssertionTtlSeconds,
        SmartTokenClient.DefaultMaxRetries);
    private bool _enableTokenCache = true;
    private int _tokenCacheMarginSeconds = SmartTokenClient.DefaultTokenCacheMarginSeconds;
    private int _tokenCacheMaxEntries = SmartTokenClient.DefaultTokenCacheMaxEntries;
    private ILogger? _logger;

    internal string? HubCtxIg => _hubCtxIg;

    internal string? HubCtxVersao => _hubCtxVersao;

    internal SmartTokenClientBuilder()
    {
    }

    /// <summary>Define a URL do token endpoint.</summary>
    public SmartTokenClientBuilder TokenEndpoint(string tokenEndpoint)
    {
        _tokenEndpoint = tokenEndpoint;
        return this;
    }

    /// <summary>
    /// Define a base FHIR para descoberta via <c>/.well-known/smart-configuration</c>.
    /// Mutuamente exclusivo com <see cref="TokenEndpoint"/>.
    /// </summary>
    public SmartTokenClientBuilder FhirBase(string fhirBaseUrl)
    {
        _discoveryBaseUrl = fhirBaseUrl;
        return this;
    }

    /// <summary>Define o identificador do cliente (Ganesha).</summary>
    public SmartTokenClientBuilder ClientId(string clientId)
    {
        _clientId = clientId;
        return this;
    }

    /// <summary>Caminho da chave privada PEM. Mutuamente exclusivo com <see cref="SigningStrategy"/>.</summary>
    public SmartTokenClientBuilder PrivateKeyPem(string privateKeyPem)
    {
        _signing.SetPrivateKeyPem(privateKeyPem);
        return this;
    }

    /// <summary>Senha da chave PEM; o array é zerado ao final de <see cref="Build"/>/<see cref="BuildAsync"/>.</summary>
    public SmartTokenClientBuilder PrivateKeyPassword(char[] password)
    {
        _signing.SetPrivateKeyPassword(password);
        return this;
    }

    /// <summary>Estratégia de assinatura pronta (HSM, cofre). Mutuamente exclusivo com PEM.</summary>
    public SmartTokenClientBuilder SigningStrategy(ISigningStrategy signingStrategy)
    {
        _signing.SetSigningStrategy(signingStrategy);
        return this;
    }

    /// <summary>Caminho do certificado PEM do cliente (mTLS e consistência chave-cert).</summary>
    public SmartTokenClientBuilder CertificatePem(string certificatePem)
    {
        _tls.SetCertificatePem(certificatePem);
        return this;
    }

    /// <summary>
    /// PKCS#12 do cliente: assinatura do JWT e mTLS com o mesmo certificado (equivalente a <c>clientKeyStore</c> no Java).
    /// Mutuamente exclusivo com PEM e <see cref="SigningStrategy"/>.
    /// </summary>
    public SmartTokenClientBuilder ClientPkcs12(string pkcs12Path, string alias, char[] password)
    {
        ArgumentNullException.ThrowIfNull(pkcs12Path);
        ArgumentNullException.ThrowIfNull(alias);
        var bytes = File.ReadAllBytes(pkcs12Path);
        _signing.SetPkcs12(bytes, alias, password);
        return this;
    }

    /// <inheritdoc cref="ClientPkcs12(string, string, char[])"/>
    public SmartTokenClientBuilder ClientPkcs12(byte[] pkcs12, string alias, char[] password)
    {
        ArgumentNullException.ThrowIfNull(pkcs12);
        ArgumentNullException.ThrowIfNull(alias);
        _signing.SetPkcs12(pkcs12, alias, password);
        return this;
    }

    /// <summary>Certificado de cliente com chave privada para mTLS (PKCS#12 / certificado em memória).</summary>
    public SmartTokenClientBuilder ClientCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        _tls.SetClientCertificate(certificate);
        return this;
    }

    /// <summary>Trust anchor do servidor a partir de arquivo PEM.</summary>
    public SmartTokenClientBuilder ServerTrustAnchor(string? serverTrustAnchor)
    {
        _tls.SetServerTrustAnchorPath(serverTrustAnchor);
        return this;
    }

    /// <summary>Trust anchor do servidor já carregado em memória.</summary>
    public SmartTokenClientBuilder ServerTrustAnchor(X509Certificate2? serverTrustAnchorCert)
    {
        _tls.SetServerTrustAnchorCert(serverTrustAnchorCert);
        return this;
    }

    /// <summary>Protocolo TLS (padrão <c>TLSv1.3</c>).</summary>
    public SmartTokenClientBuilder TlsProtocol(string tlsProtocol)
    {
        _tls.SetTlsProtocol(tlsProtocol);
        return this;
    }

    /// <summary>Algoritmo JWT do header <c>alg</c> (padrão RS384).</summary>
    public SmartTokenClientBuilder JwtAlgorithm(string jwtAlgorithm)
    {
        _signing.SetJwtAlgorithm(jwtAlgorithm);
        return this;
    }

    /// <summary>
    /// Define o claim <c>hub_ctx</c> (IG e versão SemVer). Validado na chamada (RF-01.3).
    /// </summary>
    public SmartTokenClientBuilder HubContext(string? ig, string? versao)
    {
        SmartTokenClient.ValidateHubContext(ig, versao);
        _hubCtxIg = ig;
        _hubCtxVersao = versao;
        return this;
    }

    /// <summary>Identificador <c>kid</c> do header JWT.</summary>
    public SmartTokenClientBuilder KeyId(string keyId)
    {
        _signing.SetKeyId(keyId);
        return this;
    }

    /// <summary>Timeout de conexão TCP.</summary>
    public SmartTokenClientBuilder ConnectTimeout(TimeSpan connectTimeout)
    {
        _faultToleranceConfig = new FaultToleranceConfig(
            connectTimeout,
            _faultToleranceConfig.RequestTimeout,
            _faultToleranceConfig.AssertionTtlSeconds,
            _faultToleranceConfig.MaxRetries);
        return this;
    }

    /// <summary>Timeout da requisição HTTP completa.</summary>
    public SmartTokenClientBuilder RequestTimeout(TimeSpan requestTimeout)
    {
        _faultToleranceConfig = new FaultToleranceConfig(
            _faultToleranceConfig.ConnectTimeout,
            requestTimeout,
            _faultToleranceConfig.AssertionTtlSeconds,
            _faultToleranceConfig.MaxRetries);
        return this;
    }

    /// <summary>TTL do client_assertion em segundos; ≤ 0 usa o padrão.</summary>
    public SmartTokenClientBuilder AssertionTtlSeconds(int assertionTtlSeconds)
    {
        _faultToleranceConfig = new FaultToleranceConfig(
            _faultToleranceConfig.ConnectTimeout,
            _faultToleranceConfig.RequestTimeout,
            assertionTtlSeconds,
            _faultToleranceConfig.MaxRetries);
        return this;
    }

    /// <summary>Total de tentativas em falhas transitórias; ≤ 0 usa o padrão.</summary>
    public SmartTokenClientBuilder MaxRetries(int maxRetries)
    {
        _faultToleranceConfig = new FaultToleranceConfig(
            _faultToleranceConfig.ConnectTimeout,
            _faultToleranceConfig.RequestTimeout,
            _faultToleranceConfig.AssertionTtlSeconds,
            maxRetries);
        return this;
    }

    /// <summary>Habilita ou desabilita o cache de tokens (padrão: habilitado).</summary>
    public SmartTokenClientBuilder EnableTokenCache(bool enableTokenCache)
    {
        _enableTokenCache = enableTokenCache;
        return this;
    }

    /// <summary>Margem de renovação do cache, em segundos; ≤ 0 usa o padrão.</summary>
    public SmartTokenClientBuilder TokenCacheMarginSeconds(int tokenCacheMarginSeconds)
    {
        _tokenCacheMarginSeconds = tokenCacheMarginSeconds;
        return this;
    }

    /// <summary>Teto LRU de scopes no cache; valor ≤ 0 faz <see cref="Build"/> falhar.</summary>
    public SmartTokenClientBuilder TokenCacheMaxEntries(int tokenCacheMaxEntries)
    {
        _tokenCacheMaxEntries = tokenCacheMaxEntries;
        return this;
    }

    /// <summary>Logger opcional (padrão: nenhum).</summary>
    public SmartTokenClientBuilder Logger(ILogger logger)
    {
        _logger = logger;
        return this;
    }

    /// <summary>
    /// Substitui o handler HTTP — destinado a testes. Não faz parte da API pública estável.
    /// </summary>
    internal SmartTokenClientBuilder HttpMessageHandler(HttpMessageHandler handler)
    {
        _tls.SetCustomHandler(handler);
        return this;
    }

    /// <summary>
    /// Constrói o cliente de forma síncrona (bloqueia na descoberta, se houver).
    /// </summary>
    public SmartTokenClient Build()
    {
        return BuildAsync().GetAwaiter().GetResult();
    }

    /// <summary>Constrói o cliente, resolvendo descoberta SMART quando configurada.</summary>
    public async Task<SmartTokenClient> BuildAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            return await DoBuildAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _signing.ClearSecrets();
        }
    }

    /// <summary>
    /// Descobre o <c>token_endpoint</c> a partir da base FHIR (RF-09).
    /// </summary>
    public static Task<string> DiscoverTokenEndpointAsync(
        string fhirBaseUrl,
        TimeSpan connectTimeout,
        TimeSpan requestTimeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fhirBaseUrl);
        var handler = new SocketsHttpHandler { ConnectTimeout = connectTimeout };
        return SmartConfigurationDiscovery.DiscoverTokenEndpointAsync(
            fhirBaseUrl,
            handler,
            requestTimeout,
            disposeHandler: true,
            cancellationToken);
    }

    private async Task<SmartTokenClient> DoBuildAsync(CancellationToken cancellationToken)
    {
        ValidateRequiredConfiguration();
        var credentials = _signing.Resolve();
        var cert = _tls.LoadCertificate() ?? credentials.ClientCertificate;
        var handler = _tls.ResolveHandler(_faultToleranceConfig.ConnectTimeout, credentials.ClientKey, cert);
        var disposeHandler = _tls.CustomHandler is null;
        try
        {
            var effectiveTokenEndpoint = await ResolveTokenEndpointAsync(handler, disposeHandler, cancellationToken)
                .ConfigureAwait(false);
            var mtlsCert = _tls.CustomHandler is null
                ? _tls.ResolveClientCertificate(credentials.ClientKey, cert)
                : cert;

            return new SmartTokenClient(
                credentials.Strategy,
                _faultToleranceConfig,
                effectiveTokenEndpoint,
                _clientId!,
                _signing.JwtAlgorithm,
                _signing.KeyId,
                _hubCtxIg,
                _hubCtxVersao,
                timeProvider: null,
                _enableTokenCache,
                _tokenCacheMarginSeconds,
                _tokenCacheMaxEntries,
                handler,
                disposeHandler,
                delayAsync: null,
                _logger,
                mtlsCert ?? cert);
        }
        catch
        {
            if (disposeHandler)
            {
                handler.Dispose();
            }

            throw;
        }
    }

    private void ValidateRequiredConfiguration()
    {
        if (_tokenEndpoint is not null && _discoveryBaseUrl is not null)
        {
            throw new InvalidOperationException("Defina tokenEndpoint OU fhirBase, n\u00e3o ambos");
        }

        if (_tokenEndpoint is null && _discoveryBaseUrl is null)
        {
            throw new InvalidOperationException("\u00c9 obrigat\u00f3rio definir tokenEndpoint ou fhirBase");
        }

        ArgumentNullException.ThrowIfNull(_clientId);
        if (_tokenEndpoint is not null)
        {
            SmartConfigurationDiscovery.RequireHttps(_tokenEndpoint, "tokenEndpoint");
        }

        if (_discoveryBaseUrl is not null)
        {
            SmartConfigurationDiscovery.RequireHttps(_discoveryBaseUrl, "fhirBase");
        }
    }

    private Task<string> ResolveTokenEndpointAsync(
        HttpMessageHandler handler,
        bool disposeHandler,
        CancellationToken cancellationToken)
    {
        if (_tokenEndpoint is not null)
        {
            return Task.FromResult(_tokenEndpoint);
        }

        return SmartConfigurationDiscovery.DiscoverTokenEndpointAsync(
            _discoveryBaseUrl!,
            handler,
            _faultToleranceConfig.RequestTimeout,
            disposeHandler: false,
            cancellationToken);
    }
}

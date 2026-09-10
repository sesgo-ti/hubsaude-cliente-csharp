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
    /// <param name="tokenEndpoint">URL HTTPS do token endpoint (RF-17).</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder TokenEndpoint(string tokenEndpoint)
    {
        _tokenEndpoint = tokenEndpoint;
        return this;
    }

    /// <summary>
    /// Define a base FHIR para descoberta via <c>/.well-known/smart-configuration</c>.
    /// Mutuamente exclusivo com <see cref="TokenEndpoint"/>.
    /// </summary>
    /// <param name="fhirBaseUrl">URL HTTPS da base FHIR.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder FhirBase(string fhirBaseUrl)
    {
        _discoveryBaseUrl = fhirBaseUrl;
        return this;
    }

    /// <summary>Define o identificador do cliente (Ganesha).</summary>
    /// <param name="clientId">Valor de <c>iss</c>/<c>sub</c> do assertion.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder ClientId(string clientId)
    {
        _clientId = clientId;
        return this;
    }

    /// <summary>Caminho da chave privada PEM. Mutuamente exclusivo com <see cref="SigningStrategy"/>.</summary>
    /// <param name="privateKeyPem">Caminho do arquivo PEM da chave privada.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder PrivateKeyPem(string privateKeyPem)
    {
        _signing.SetPrivateKeyPem(privateKeyPem);
        return this;
    }

    /// <summary>Senha da chave PEM; o array é zerado ao final de <see cref="Build"/>/<see cref="BuildAsync"/>.</summary>
    /// <param name="password">Senha em claro; o chamador pode reutilizar o array até o <see cref="Build"/>.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder PrivateKeyPassword(char[] password)
    {
        _signing.SetPrivateKeyPassword(password);
        return this;
    }

    /// <summary>Estratégia de assinatura pronta (HSM/PKCS#11, cofre). Mutuamente exclusivo com PEM; pode ser combinada com PKCS#12 só para mTLS.</summary>
    /// <param name="signingStrategy">Estratégia que assina o <c>client_assertion</c>.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder SigningStrategy(ISigningStrategy signingStrategy)
    {
        _signing.SetSigningStrategy(signingStrategy);
        return this;
    }

    /// <summary>Caminho do certificado PEM do cliente (mTLS e consistência chave-cert).</summary>
    /// <param name="certificatePem">Caminho do arquivo PEM do certificado.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder CertificatePem(string certificatePem)
    {
        _tls.SetCertificatePem(certificatePem);
        return this;
    }

    /// <summary>
    /// PKCS#12 do cliente. Isolado, assina o JWT e configura mTLS com o mesmo
    /// certificado. Com <see cref="SigningStrategy"/> (HSM/PKCS#11), o PKCS#12
    /// é usado apenas no mTLS. Mutuamente exclusivo com PEM.
    /// </summary>
    /// <param name="pkcs12Path">Caminho do arquivo PFX/P12.</param>
    /// <param name="alias">Alias ou nome simples da entrada com chave privada.</param>
    /// <param name="password">Senha do PKCS#12.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="pkcs12Path"/> ou <paramref name="alias"/> é nulo.
    /// </exception>
    /// <exception cref="IOException">Falha ao ler o arquivo.</exception>
    public SmartTokenClientBuilder ClientPkcs12(string pkcs12Path, string alias, char[] password)
    {
        ArgumentNullException.ThrowIfNull(pkcs12Path);
        ArgumentNullException.ThrowIfNull(alias);
        var bytes = File.ReadAllBytes(pkcs12Path);
        _signing.SetPkcs12(bytes, alias, password);
        return this;
    }

    /// <inheritdoc cref="ClientPkcs12(string, string, char[])"/>
    /// <param name="pkcs12">Bytes do arquivo PFX/P12.</param>
    /// <param name="alias">Alias ou nome simples da entrada com chave privada.</param>
    /// <param name="password">Senha do PKCS#12.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="pkcs12"/> ou <paramref name="alias"/> é nulo.
    /// </exception>
    public SmartTokenClientBuilder ClientPkcs12(byte[] pkcs12, string alias, char[] password)
    {
        ArgumentNullException.ThrowIfNull(pkcs12);
        ArgumentNullException.ThrowIfNull(alias);
        _signing.SetPkcs12(pkcs12, alias, password);
        return this;
    }

    /// <summary>Certificado de cliente com chave privada para mTLS (PKCS#12 / certificado em memória).</summary>
    /// <param name="certificate">Certificado já carregado, preferencialmente com chave persistida no Windows.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="certificate"/> é nulo.</exception>
    public SmartTokenClientBuilder ClientCertificate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        _tls.SetClientCertificate(certificate);
        return this;
    }

    /// <summary>Trust anchor do servidor a partir de arquivo PEM.</summary>
    /// <param name="serverTrustAnchor">Caminho do PEM da CA; nulo usa o trust store do sistema.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder ServerTrustAnchor(string? serverTrustAnchor)
    {
        _tls.SetServerTrustAnchorPath(serverTrustAnchor);
        return this;
    }

    /// <summary>Trust anchor do servidor já carregado em memória.</summary>
    /// <param name="serverTrustAnchorCert">Certificado da CA; nulo usa o trust store do sistema.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder ServerTrustAnchor(X509Certificate2? serverTrustAnchorCert)
    {
        _tls.SetServerTrustAnchorCert(serverTrustAnchorCert);
        return this;
    }

    /// <summary>Protocolo TLS (padrão <c>TLSv1.3</c>).</summary>
    /// <param name="tlsProtocol">Identificador do protocolo (ex.: <c>TLSv1.2</c>, <c>TLSv1.3</c>).</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder TlsProtocol(string tlsProtocol)
    {
        _tls.SetTlsProtocol(tlsProtocol);
        return this;
    }

    /// <summary>Algoritmo JWT do header <c>alg</c> (padrão RS384).</summary>
    /// <param name="jwtAlgorithm">Algoritmo JWT (ex.: <c>RS384</c>, <c>ES384</c>).</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder JwtAlgorithm(string jwtAlgorithm)
    {
        _signing.SetJwtAlgorithm(jwtAlgorithm);
        return this;
    }

    /// <summary>
    /// Define o claim <c>hub_ctx</c> (IG e versão SemVer). Validado na chamada (RF-01.3).
    /// </summary>
    /// <param name="ig">Identificador da IG (minúsculas, 2–31 caracteres).</param>
    /// <param name="versao">Versão SemVer completa (<c>MAJOR.MINOR.PATCH</c>).</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    /// <exception cref="ArgumentException"><paramref name="ig"/> ou <paramref name="versao"/> é inválido.</exception>
    public SmartTokenClientBuilder HubContext(string? ig, string? versao)
    {
        SmartTokenClient.ValidateHubContext(ig, versao);
        _hubCtxIg = ig;
        _hubCtxVersao = versao;
        return this;
    }

    /// <summary>Identificador <c>kid</c> do header JWT.</summary>
    /// <param name="keyId">Valor de <c>kid</c>; espaços em branco são ignorados na construção.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder KeyId(string keyId)
    {
        _signing.SetKeyId(keyId);
        return this;
    }

    /// <summary>Timeout de conexão TCP.</summary>
    /// <param name="connectTimeout">Timeout não negativo.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="connectTimeout"/> é negativo.</exception>
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
    /// <param name="requestTimeout">Timeout não negativo.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="requestTimeout"/> é negativo.</exception>
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
    /// <param name="assertionTtlSeconds">TTL em segundos; não positivo usa <see cref="SmartTokenClient.DefaultAssertionTtlSeconds"/>.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
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
    /// <param name="maxRetries">Tentativas totais; não positivo usa <see cref="SmartTokenClient.DefaultMaxRetries"/>.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
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
    /// <param name="enableTokenCache"><c>true</c> para cachear tokens por scope.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder EnableTokenCache(bool enableTokenCache)
    {
        _enableTokenCache = enableTokenCache;
        return this;
    }

    /// <summary>Margem de renovação do cache, em segundos; ≤ 0 usa o padrão.</summary>
    /// <param name="tokenCacheMarginSeconds">Segundos antes de <c>expires_in</c> para renovar.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder TokenCacheMarginSeconds(int tokenCacheMarginSeconds)
    {
        _tokenCacheMarginSeconds = tokenCacheMarginSeconds;
        return this;
    }

    /// <summary>Teto LRU de scopes no cache; valor ≤ 0 faz <see cref="Build"/> falhar.</summary>
    /// <param name="tokenCacheMaxEntries">Número máximo de entradas no cache LRU.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
    public SmartTokenClientBuilder TokenCacheMaxEntries(int tokenCacheMaxEntries)
    {
        _tokenCacheMaxEntries = tokenCacheMaxEntries;
        return this;
    }

    /// <summary>Logger opcional (padrão: nenhum).</summary>
    /// <param name="logger">Instância de <see cref="ILogger"/>.</param>
    /// <returns>Esta instância, para encadeamento fluente.</returns>
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
    /// <returns>Cliente pronto para <see cref="SmartTokenClient.ObtainTokenAsync"/>.</returns>
    /// <exception cref="ArgumentNullException">Configuração obrigatória ausente (ex.: <c>clientId</c>).</exception>
    /// <exception cref="InvalidOperationException">Fontes de assinatura conflitantes ou endpoint não definido.</exception>
    /// <exception cref="SmartTokenException">Material criptográfico inválido.</exception>
    public SmartTokenClient Build()
    {
        return BuildAsync().GetAwaiter().GetResult();
    }

    /// <summary>Constrói o cliente, resolvendo descoberta SMART quando configurada.</summary>
    /// <param name="cancellationToken">Token de cancelamento da descoberta e da construção.</param>
    /// <returns>Cliente pronto para <see cref="SmartTokenClient.ObtainTokenAsync"/>.</returns>
    /// <exception cref="ArgumentNullException">Configuração obrigatória ausente (ex.: <c>clientId</c>).</exception>
    /// <exception cref="InvalidOperationException">Fontes de assinatura conflitantes ou endpoint não definido.</exception>
    /// <exception cref="SmartTokenException">Material criptográfico inválido.</exception>
    /// <exception cref="OperationCanceledException">A operação foi cancelada.</exception>
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
    /// <param name="fhirBaseUrl">URL HTTPS da base FHIR.</param>
    /// <param name="connectTimeout">Timeout de conexão TCP.</param>
    /// <param name="requestTimeout">Timeout da requisição HTTP completa.</param>
    /// <param name="cancellationToken">Token de cancelamento.</param>
    /// <returns>URL do token endpoint anunciada em <c>/.well-known/smart-configuration</c>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="fhirBaseUrl"/> é nulo.</exception>
    /// <exception cref="SmartTokenException">Descoberta inválida ou endpoint ausente.</exception>
    /// <exception cref="OperationCanceledException">A operação foi cancelada.</exception>
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

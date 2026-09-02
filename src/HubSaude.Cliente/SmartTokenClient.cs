// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace HubSaude.Cliente;

/// <summary>
/// Cliente SMART Backend Services para obtenção de access tokens.
/// </summary>
/// <remarks>
/// <para>
/// Abstrai toda a complexidade de leitura de chave privada PEM, montagem do
/// <c>client_assertion</c> JWT (assinado com RS384 por padrão) e comunicação HTTP com o
/// token endpoint. Destinada a aplicações cliente que precisam se autenticar junto ao
/// HubSaúde utilizando o fluxo SMART Backend Services.
/// </para>
/// <para>
/// Instância task-safe e reutilizável. Compõe uma <see cref="ISigningStrategy"/> (padrão
/// Strategy) para a assinatura do <c>client_assertion</c>. Construção pública apenas via
/// <see cref="CreateBuilder"/>.
/// </para>
/// </remarks>
public sealed partial class SmartTokenClient : IDisposable, IAsyncDisposable
{
    /// <summary>TTL padrão do <c>client_assertion</c>, em segundos.</summary>
    public const int DefaultAssertionTtlSeconds = 60;

    /// <summary>Timeout padrão de conexão TCP.</summary>
    public static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Timeout padrão da requisição HTTP completa.</summary>
    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Número máximo padrão de tentativas (1 inicial + retries).</summary>
    public const int DefaultMaxRetries = 3;

    /// <summary>Margem padrão, em segundos, para renovar o token antes da expiração.</summary>
    public const int DefaultTokenCacheMarginSeconds = 30;

    /// <summary>Quantidade máxima padrão de scopes retidos no cache LRU.</summary>
    public const int DefaultTokenCacheMaxEntries = 1_000;

    /// <summary>Protocolo TLS padrão.</summary>
    public const string DefaultTlsProtocol = "TLSv1.3";

    /// <summary>Algoritmo JWT padrão aceito pelo HubSaúde.</summary>
    public const string DefaultJwtAlgorithm = "RS384";

    private const string GrantType = "client_credentials";
    private const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private const int FormBodyInitialCapacity = 128;

    private readonly HttpClient _httpClient;
    private readonly TokenCacheStrategy _tokenCache;
    private readonly ErrorClassifier _errorClassifier;
    private readonly ILogger _logger;
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync;
    private int _disposed;
    private int _inFlight;

    internal SmartTokenClient(ISigningStrategy signingStrategy, FaultToleranceConfig faultTolerance)
        : this(
            signingStrategy,
            faultTolerance,
            tokenEndpoint: "https://localhost/auth/token",
            clientId: "test-client")
    {
    }

    internal SmartTokenClient(
        ISigningStrategy signingStrategy,
        FaultToleranceConfig faultTolerance,
        string tokenEndpoint,
        string clientId,
        string? jwtAlgorithm = null,
        string? keyId = null,
        string? hubCtxIg = null,
        string? hubCtxVersao = null,
        TimeProvider? timeProvider = null,
        bool enableTokenCache = true,
        int tokenCacheMarginSeconds = DefaultTokenCacheMarginSeconds,
        int tokenCacheMaxEntries = DefaultTokenCacheMaxEntries,
        HttpMessageHandler? httpHandler = null,
        bool disposeHandler = true,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null,
        ILogger? logger = null,
        X509Certificate2? clientCertificate = null)
    {
        ArgumentNullException.ThrowIfNull(signingStrategy);
        ArgumentNullException.ThrowIfNull(faultTolerance);
        ArgumentNullException.ThrowIfNull(tokenEndpoint);
        ArgumentNullException.ThrowIfNull(clientId);

        SigningStrategy = signingStrategy;
        FaultTolerance = faultTolerance;
        TokenEndpoint = tokenEndpoint;
        ClientId = clientId;
        JwtAlgorithm = jwtAlgorithm ?? DefaultJwtAlgorithm;
        SigningStrategyFactory.JwtAlgorithmToJava(JwtAlgorithm);
        KeyId = string.IsNullOrWhiteSpace(keyId) ? null : keyId;
        if (hubCtxIg is not null || hubCtxVersao is not null)
        {
            ValidateHubContext(hubCtxIg, hubCtxVersao);
        }

        HubCtxIg = hubCtxIg;
        HubCtxVersao = hubCtxVersao;
        Time = timeProvider ?? TimeProvider.System;
        _logger = logger ?? NullLogger.Instance;
        _delayAsync = delayAsync ?? ((delay, ct) => Task.Delay(delay, Time, ct));
        if (clientCertificate is not null)
        {
            CertificateValidator.CheckValidity(clientCertificate, clientCertificate.Subject);
            KeyCertificateConsistency.VerifyStrategy(signingStrategy, clientCertificate);
        }

        var margin = tokenCacheMarginSeconds > 0
            ? tokenCacheMarginSeconds
            : DefaultTokenCacheMarginSeconds;
        _tokenCache = new TokenCacheStrategy(
            enableTokenCache,
            margin,
            clientId,
            tokenCacheMaxEntries,
            Time,
            _logger);
        _errorClassifier = new ErrorClassifier(clientId, tokenEndpoint, _logger);

        var handler = httpHandler ?? new SocketsHttpHandler
        {
            ConnectTimeout = faultTolerance.ConnectTimeout,
        };
        _httpClient = new HttpClient(handler, disposeHandler)
        {
            Timeout = faultTolerance.RequestTimeout,
        };
    }

    /// <summary>Estratégia de assinatura composta por este cliente.</summary>
    internal ISigningStrategy SigningStrategy { get; }

    /// <summary>Configuração de tolerância a falhas aplicada às requisições.</summary>
    internal FaultToleranceConfig FaultTolerance { get; }

    /// <summary>URL efetiva do token endpoint (RF-17).</summary>
    public string TokenEndpoint { get; }

    /// <summary>Identificador do cliente (iss/sub do assertion).</summary>
    public string ClientId { get; }

    /// <summary>Algoritmo JWT <c>alg</c> configurado (RF-16).</summary>
    public string JwtAlgorithm { get; }

    /// <summary><c>kid</c> do header JWT, quando configurado.</summary>
    public string? KeyId { get; }

    internal string? HubCtxIg { get; }

    internal string? HubCtxVersao { get; }

    internal TimeProvider Time { get; }

    internal int TokenCacheSize => _tokenCache.Size;

    /// <summary>
    /// Inicia a construção fluente do cliente. Única entrada pública suportada.
    /// </summary>
    public static SmartTokenClientBuilder CreateBuilder()
    {
        return new SmartTokenClientBuilder();
    }

    /// <summary>
    /// Obtém um access token para os scopes informados (RF-17).
    /// </summary>
    public async Task<string> ObtainTokenAsync(string? scope, CancellationToken cancellationToken = default)
    {
        var response = await ObtainTokenResponseAsync(scope, cancellationToken).ConfigureAwait(false);
        return response.AccessToken;
    }

    /// <summary>
    /// Invalida o cache de todos os scopes (RF-06).
    /// </summary>
    public void InvalidateCache()
    {
        _tokenCache.InvalidateAll();
    }

    /// <summary>
    /// Invalida o cache do scope informado (RF-06).
    /// </summary>
    public void InvalidateCache(string? scope)
    {
        _tokenCache.Invalidate(NormalizeScope(scope));
    }

    /// <summary>
    /// Valida o par <c>hub_ctx.ig</c> / <c>hub_ctx.versao</c> (RF-01.3).
    /// </summary>
    internal static void ValidateHubContext(string? ig, string? versao)
    {
        if (ig is null || !HubCtxIgRegex().IsMatch(ig))
        {
            throw new ArgumentException(
                "hub_ctx.ig inv\u00e1lido: '" + ig + "' (use min\u00fasculas, d\u00edgitos e h\u00edfen,"
                + " iniciando por letra, 2 a 31 caracteres)",
                nameof(ig));
        }

        if (versao is null || !HubCtxVersaoRegex().IsMatch(versao))
        {
            throw new ArgumentException(
                "hub_ctx.versao inv\u00e1lido: '" + versao
                + "' (use SemVer completo MAJOR.MINOR.PATCH, ex.: 0.0.1)",
                nameof(versao));
        }
    }

    /// <summary>
    /// Constrói o JWT <c>client_assertion</c> compacto (RF-01).
    /// </summary>
    internal string BuildClientAssertion()
    {
        EnsureOpen();

        var now = Time.GetUtcNow();
        var iat = now.ToUnixTimeSeconds();
        var exp = now.AddSeconds(FaultTolerance.AssertionTtlSeconds).ToUnixTimeSeconds();
        var jti = Guid.NewGuid().ToString();

        var payload = new JsonObject
        {
            ["iss"] = ClientId,
            ["sub"] = ClientId,
            ["aud"] = TokenEndpoint,
            ["iat"] = iat,
            ["exp"] = exp,
            ["jti"] = jti,
        };
        if (HubCtxIg is not null && HubCtxVersao is not null)
        {
            payload["hub_ctx"] = new JsonObject
            {
                ["ig"] = HubCtxIg,
                ["versao"] = HubCtxVersao,
            };
        }

        var header = new JsonObject
        {
            ["alg"] = JwtAlgorithm,
            ["typ"] = "JWT",
        };
        if (KeyId is not null)
        {
            header["kid"] = KeyId;
        }

        string payloadJson;
        string headerJson;
        try
        {
            payloadJson = payload.ToJsonString();
            headerJson = header.ToJsonString();
        }
        catch (Exception ex)
        {
            throw new SmartTokenException("Falha ao serializar payload do JWT", ex);
        }

        var headerB64 = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(headerJson));
        var payloadB64 = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(payloadJson));
        var dataToSign = headerB64 + "." + payloadB64;
        var signature = SigningStrategy.Sign(Encoding.UTF8.GetBytes(dataToSign));
        var signatureB64 = Base64Url.EncodeToString(signature);
        return dataToSign + "." + signatureB64;
    }

    /// <summary>
    /// Monta o corpo <c>application/x-www-form-urlencoded</c> do token endpoint (RF-02).
    /// </summary>
    public static string BuildFormBody(string clientId, string assertion, string? scope)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        ArgumentNullException.ThrowIfNull(assertion);

        var sb = new StringBuilder(FormBodyInitialCapacity)
            .Append("grant_type=").Append(Encode(GrantType))
            .Append("&client_id=").Append(Encode(clientId))
            .Append("&client_assertion_type=").Append(Encode(AssertionType))
            .Append("&client_assertion=").Append(Encode(assertion));
        if (!string.IsNullOrWhiteSpace(scope))
        {
            sb.Append("&scope=").Append(Encode(scope));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Percent-encoding UTF-8 no estilo <c>application/x-www-form-urlencoded</c> (espaço como <c>+</c>).
    /// </summary>
    public static string Encode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return Uri.EscapeDataString(value).Replace("%20", "+", StringComparison.Ordinal);
    }

    /// <summary>
    /// Extrai o <c>access_token</c> de uma resposta JSON do token endpoint.
    /// </summary>
    public static string ExtractAccessToken(string jsonBody)
    {
        return ParseTokenResponse(jsonBody).AccessToken;
    }

    /// <summary>
    /// Verifica se chave privada e certificado formam um par (RF-15).
    /// </summary>
    public static void VerifyKeyPairConsistency(AsymmetricAlgorithm privateKey, X509Certificate2 certificate)
    {
        KeyCertificateConsistency.VerifyKeyPair(privateKey, certificate);
    }

    internal static TokenResponse ParseTokenResponse(string jsonBody, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(jsonBody);
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(jsonBody);
        }
        catch (JsonException ex)
        {
            throw new SmartTokenException("Resposta JSON inv\u00e1lida do token endpoint", ex);
        }

        using (document)
        {
            var root = document.RootElement;
            if (!root.TryGetProperty("access_token", out var tokenNode)
                || tokenNode.ValueKind != JsonValueKind.String
                || string.IsNullOrWhiteSpace(tokenNode.GetString()))
            {
                throw new SmartTokenException("Resposta n\u00e3o cont\u00e9m 'access_token'");
            }

            var expiresIn = TokenResponseGuard.SanitizeExpiresIn(root, logger);
            return new TokenResponse(tokenNode.GetString()!, expiresIn, jsonBody);
        }
    }

    internal static string NormalizeScope(string? scope)
    {
        return scope is null ? string.Empty : scope.Trim();
    }

    /// <summary>
    /// Falha se o cliente já foi encerrado.
    /// </summary>
    internal void EnsureOpen()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
    }

    internal SemaphoreSlim ScopeLockFor(string scope)
    {
        return _tokenCache.LockFor(NormalizeScope(scope));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        await WaitForIdleAsync().ConfigureAwait(false);
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    private void DisposeCore()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        SpinWait.SpinUntil(() => Volatile.Read(ref _inFlight) == 0, TimeSpan.FromSeconds(30));
        try
        {
            _httpClient.Dispose();
        }
        finally
        {
            _tokenCache.InvalidateAll();
            _tokenCache.DisposeLocks();
            _logger.LogDebug("SmartTokenClient fechado para clientId={ClientId}", ClientId);
        }
    }

    private async Task WaitForIdleAsync()
    {
        var start = Time.GetUtcNow();
        while (Volatile.Read(ref _inFlight) != 0)
        {
            if (Time.GetUtcNow() - start > TimeSpan.FromSeconds(30))
            {
                break;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(10), Time, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private void BeginOperation()
    {
        EnsureOpen();
        Interlocked.Increment(ref _inFlight);
        if (Volatile.Read(ref _disposed) != 0)
        {
            Interlocked.Decrement(ref _inFlight);
            throw new ObjectDisposedException(nameof(SmartTokenClient));
        }
    }

    private void EndOperation()
    {
        Interlocked.Decrement(ref _inFlight);
    }

    /// <summary>
    /// Resposta do token endpoint (RF-03, RF-17).
    /// </summary>
    /// <param name="AccessToken">Token de acesso emitido.</param>
    /// <param name="ExpiresIn">Validade restante, em segundos.</param>
    /// <param name="RawJson">JSON cru; nulo quando servido do cache.</param>
    public sealed record TokenResponse(string AccessToken, int ExpiresIn, string? RawJson)
    {
        /// <inheritdoc />
        public override string ToString()
        {
            return "TokenResponse[accessToken=[REDACTED], expiresIn=" + ExpiresIn
                + ", rawJson=[REDACTED]]";
        }
    }

    [GeneratedRegex("^[a-z][a-z0-9-]{1,30}$", RegexOptions.CultureInvariant)]
    private static partial Regex HubCtxIgRegex();

    [GeneratedRegex("^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)$", RegexOptions.CultureInvariant)]
    private static partial Regex HubCtxVersaoRegex();
}

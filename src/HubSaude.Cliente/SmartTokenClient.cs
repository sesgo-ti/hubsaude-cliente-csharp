// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente;

/// <summary>
/// Cliente SMART Backend Services para obtenção de access tokens.
/// </summary>
/// <remarks>
/// Instância thread-safe e reutilizável. Compõe uma
/// <see cref="ISigningStrategy"/> (padrão Strategy) para a assinatura do
/// <c>client_assertion</c>. Construção apenas via
/// <see cref="CreateBuilder"/>.
/// </remarks>
public sealed class SmartTokenClient : IDisposable, IAsyncDisposable
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

    private int _disposed;

    /// <summary>
    /// Cria o cliente com a estratégia de assinatura e a configuração de resiliência.
    /// </summary>
    /// <param name="signingStrategy">Estratégia que produz a assinatura crua do assertion.</param>
    /// <param name="faultTolerance">Timeouts, TTL do assertion e política de retry.</param>
    /// <exception cref="ArgumentNullException">Algum argumento obrigatório é nulo.</exception>
    internal SmartTokenClient(ISigningStrategy signingStrategy, FaultToleranceConfig faultTolerance)
    {
        ArgumentNullException.ThrowIfNull(signingStrategy);
        ArgumentNullException.ThrowIfNull(faultTolerance);

        SigningStrategy = signingStrategy;
        FaultTolerance = faultTolerance;
    }

    /// <summary>Estratégia de assinatura composta por este cliente.</summary>
    internal ISigningStrategy SigningStrategy { get; }

    /// <summary>Configuração de tolerância a falhas aplicada às requisições.</summary>
    internal FaultToleranceConfig FaultTolerance { get; }

    /// <summary>
    /// Inicia a construção fluente do cliente. Única entrada pública suportada.
    /// </summary>
    public static SmartTokenClientBuilder CreateBuilder()
    {
        return new SmartTokenClientBuilder();
    }

    /// <summary>
    /// Falha se o cliente já foi encerrado.
    /// </summary>
    /// <exception cref="ObjectDisposedException">O cliente foi disposto.</exception>
    internal void EnsureOpen()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        DisposeCore();
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    private void DisposeCore()
    {
        _ = Interlocked.Exchange(ref _disposed, 1);
    }
}

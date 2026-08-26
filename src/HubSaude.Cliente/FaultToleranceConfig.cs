// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente;

/// <summary>
/// Configuração imutável de tolerância a falhas do <see cref="SmartTokenClient"/>.
/// </summary>
/// <remarks>
/// Valores não positivos de <see cref="AssertionTtlSeconds"/> e
/// <see cref="MaxRetries"/> são substituídos pelos padrões do cliente (RF-18.4).
/// Timeouts negativos são rejeitados: em .NET <see cref="TimeSpan"/> é um
/// valor e não admite nulo; a validação equivalente a RF-18.6 é o intervalo
/// válido (<c>&gt;= 0</c>).
/// </remarks>
public sealed record FaultToleranceConfig
{
    /// <summary>
    /// Cria a configuração, aplicando padrões tolerantes a TTL e retries.
    /// </summary>
    /// <param name="connectTimeout">Timeout de conexão TCP.</param>
    /// <param name="requestTimeout">Timeout da requisição HTTP completa.</param>
    /// <param name="assertionTtlSeconds">TTL do JWT em segundos; ≤ 0 usa o padrão.</param>
    /// <param name="maxRetries">Tentativas totais; ≤ 0 usa o padrão.</param>
    /// <exception cref="ArgumentOutOfRangeException">Timeout negativo.</exception>
    public FaultToleranceConfig(
        TimeSpan connectTimeout,
        TimeSpan requestTimeout,
        int assertionTtlSeconds,
        int maxRetries)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(connectTimeout, TimeSpan.Zero);
        ArgumentOutOfRangeException.ThrowIfLessThan(requestTimeout, TimeSpan.Zero);

        ConnectTimeout = connectTimeout;
        RequestTimeout = requestTimeout;
        AssertionTtlSeconds = assertionTtlSeconds > 0
            ? assertionTtlSeconds
            : SmartTokenClient.DefaultAssertionTtlSeconds;
        MaxRetries = maxRetries > 0
            ? maxRetries
            : SmartTokenClient.DefaultMaxRetries;
    }

    /// <summary>Timeout máximo para estabelecer a conexão TCP.</summary>
    public TimeSpan ConnectTimeout { get; }

    /// <summary>Timeout máximo para completar a requisição HTTP.</summary>
    public TimeSpan RequestTimeout { get; }

    /// <summary>TTL do <c>client_assertion</c> em segundos.</summary>
    public int AssertionTtlSeconds { get; }

    /// <summary>Número total de tentativas em falhas transitórias de rede.</summary>
    public int MaxRetries { get; }
}

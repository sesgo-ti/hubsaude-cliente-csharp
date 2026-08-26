// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente;

/// <summary>
/// Política de retry: backoff exponencial sem jitter (RF-07.4).
/// </summary>
internal static class RetryPolicy
{
    /// <summary>
    /// Calcula o atraso antes da próxima tentativa: <c>1s × 2^(failedAttempt-1)</c>.
    /// </summary>
    /// <param name="failedAttempt">Número 1-based da tentativa que falhou.</param>
    /// <returns>Atraso sem jitter.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="failedAttempt"/> &lt; 1.</exception>
    internal static TimeSpan ComputeRetryDelay(int failedAttempt)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(failedAttempt, 1);
        return TimeSpan.FromSeconds(1) * (1L << (failedAttempt - 1));
    }
}

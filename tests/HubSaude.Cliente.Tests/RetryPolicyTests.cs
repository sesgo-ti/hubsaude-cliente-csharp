// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente.Tests;

public sealed class RetryPolicyTests
{
    [Theory]
    [InlineData(1, 1_000)]
    [InlineData(2, 2_000)]
    [InlineData(3, 4_000)]
    [InlineData(4, 8_000)]
    public void deveCalcularBackoffExponencialSemJitter(int tentativaQueFalhou, int delayEsperadoMs)
    {
        var delay = RetryPolicy.ComputeRetryDelay(tentativaQueFalhou);

        Assert.Equal(TimeSpan.FromMilliseconds(delayEsperadoMs), delay);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void deveRejeitarTentativaMenorQueUm(int tentativa)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => RetryPolicy.ComputeRetryDelay(tentativa));

        Assert.Equal("failedAttempt", ex.ParamName);
    }
}

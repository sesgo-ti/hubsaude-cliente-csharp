// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

namespace HubSaude.Cliente.Tests;

public sealed class FaultToleranceConfigTests
{
    private static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(30);

    [Fact]
    public void deveCriarConfigComValoresValidos()
    {
        var config = new FaultToleranceConfig(
            TimeSpan.FromSeconds(5),
            TimeSpan.FromSeconds(15),
            assertionTtlSeconds: 120,
            maxRetries: 5);

        Assert.Equal(TimeSpan.FromSeconds(5), config.ConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(15), config.RequestTimeout);
        Assert.Equal(120, config.AssertionTtlSeconds);
        Assert.Equal(5, config.MaxRetries);
    }

    [Fact]
    public void deveUsarPadraoQuandoAssertionTtlZero()
    {
        var config = new FaultToleranceConfig(
            DefaultConnectTimeout,
            DefaultRequestTimeout,
            assertionTtlSeconds: 0,
            maxRetries: 3);

        Assert.Equal(SmartTokenClient.DefaultAssertionTtlSeconds, config.AssertionTtlSeconds);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-10)]
    [InlineData(-100)]
    [InlineData(int.MinValue)]
    public void deveUsarPadraoQuandoAssertionTtlNegativo(int ttl)
    {
        var config = new FaultToleranceConfig(
            DefaultConnectTimeout,
            DefaultRequestTimeout,
            assertionTtlSeconds: ttl,
            maxRetries: 3);

        Assert.Equal(SmartTokenClient.DefaultAssertionTtlSeconds, config.AssertionTtlSeconds);
    }

    [Fact]
    public void deveUsarPadraoQuandoMaxRetriesZero()
    {
        var config = new FaultToleranceConfig(
            DefaultConnectTimeout,
            DefaultRequestTimeout,
            assertionTtlSeconds: 60,
            maxRetries: 0);

        Assert.Equal(SmartTokenClient.DefaultMaxRetries, config.MaxRetries);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(-5)]
    [InlineData(-100)]
    [InlineData(int.MinValue)]
    public void deveUsarPadraoQuandoMaxRetriesNegativo(int retries)
    {
        var config = new FaultToleranceConfig(
            DefaultConnectTimeout,
            DefaultRequestTimeout,
            assertionTtlSeconds: 60,
            maxRetries: retries);

        Assert.Equal(SmartTokenClient.DefaultMaxRetries, config.MaxRetries);
    }

    [Fact]
    public void deveLancarExcecaoQuandoConnectTimeoutNegativo()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new FaultToleranceConfig(
            TimeSpan.FromSeconds(-1),
            DefaultRequestTimeout,
            assertionTtlSeconds: 60,
            maxRetries: 3));

        Assert.Equal("connectTimeout", ex.ParamName);
    }

    [Fact]
    public void deveLancarExcecaoQuandoRequestTimeoutNegativo()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => new FaultToleranceConfig(
            DefaultConnectTimeout,
            TimeSpan.FromMilliseconds(-1),
            assertionTtlSeconds: 60,
            maxRetries: 3));

        Assert.Equal("requestTimeout", ex.ParamName);
    }

    [Fact]
    public void deveAceitarValoresLimite()
    {
        var config = new FaultToleranceConfig(
            TimeSpan.FromMilliseconds(1),
            TimeSpan.FromMilliseconds(1),
            assertionTtlSeconds: 1,
            maxRetries: 1);

        Assert.Equal(TimeSpan.FromMilliseconds(1), config.ConnectTimeout);
        Assert.Equal(TimeSpan.FromMilliseconds(1), config.RequestTimeout);
        Assert.Equal(1, config.AssertionTtlSeconds);
        Assert.Equal(1, config.MaxRetries);
    }

    [Fact]
    public void deveAceitarValoresGrandes()
    {
        var config = new FaultToleranceConfig(
            TimeSpan.FromHours(1),
            TimeSpan.FromHours(2),
            assertionTtlSeconds: 3600,
            maxRetries: 100);

        Assert.Equal(TimeSpan.FromHours(1), config.ConnectTimeout);
        Assert.Equal(TimeSpan.FromHours(2), config.RequestTimeout);
        Assert.Equal(3600, config.AssertionTtlSeconds);
        Assert.Equal(100, config.MaxRetries);
    }

    [Fact]
    public void deveSerImutavel()
    {
        var config = new FaultToleranceConfig(
            DefaultConnectTimeout,
            DefaultRequestTimeout,
            assertionTtlSeconds: 60,
            maxRetries: 3);

        Assert.Equal(config.ConnectTimeout, config.ConnectTimeout);
        Assert.Equal(config.RequestTimeout, config.RequestTimeout);
        Assert.Equal(60, config.AssertionTtlSeconds);
        Assert.Equal(3, config.MaxRetries);
    }

    [Fact]
    public void valoresPadraoDevemSerConsistentesComSmartTokenClient()
    {
        Assert.Equal(60, SmartTokenClient.DefaultAssertionTtlSeconds);
        Assert.Equal(3, SmartTokenClient.DefaultMaxRetries);
        Assert.Equal(TimeSpan.FromSeconds(10), SmartTokenClient.DefaultConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(30), SmartTokenClient.DefaultRequestTimeout);
    }
}

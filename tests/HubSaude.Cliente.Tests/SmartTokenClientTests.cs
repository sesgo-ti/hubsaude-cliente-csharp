// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using HubSaude.Cliente.Tests.Fakes;

namespace HubSaude.Cliente.Tests;

public sealed class SmartTokenClientTests
{
    [Fact]
    public void bibliotecaReferenciada_DeveExporSmartTokenClient()
    {
        var assembly = typeof(SmartTokenClient).Assembly;

        Assert.Equal("HubSaude.Cliente", assembly.GetName().Name);
    }

    [Fact]
    public void constantesPadrao_DevemSeguirAEspecificacao()
    {
        Assert.Equal(60, SmartTokenClient.DefaultAssertionTtlSeconds);
        Assert.Equal(TimeSpan.FromSeconds(10), SmartTokenClient.DefaultConnectTimeout);
        Assert.Equal(TimeSpan.FromSeconds(30), SmartTokenClient.DefaultRequestTimeout);
        Assert.Equal(3, SmartTokenClient.DefaultMaxRetries);
        Assert.Equal(30, SmartTokenClient.DefaultTokenCacheMarginSeconds);
        Assert.Equal(1_000, SmartTokenClient.DefaultTokenCacheMaxEntries);
        Assert.Equal("TLSv1.3", SmartTokenClient.DefaultTlsProtocol);
        Assert.Equal("RS384", SmartTokenClient.DefaultJwtAlgorithm);
    }

    [Fact]
    public void createBuilder_DeveSerAUnicaEntradaPublicaDeConstrucao()
    {
        var builder = SmartTokenClient.CreateBuilder();

        Assert.NotNull(builder);
        Assert.Empty(typeof(SmartTokenClient).GetConstructors(
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance));
    }

    [Fact]
    public void construtor_DeveComporAEstrategiaDeAssinatura()
    {
        var strategy = new FakeSigningStrategy();
        var config = CreateDefaultFaultTolerance();

        using var client = new SmartTokenClient(strategy, config);

        Assert.Same(strategy, client.SigningStrategy);
        Assert.Equal(config, client.FaultTolerance);
    }

    [Fact]
    public void construtor_DeveRejeitarEstrategiaNula()
    {
        var ex = Assert.Throws<ArgumentNullException>(
            () => new SmartTokenClient(null!, CreateDefaultFaultTolerance()));

        Assert.Equal("signingStrategy", ex.ParamName);
    }

    [Fact]
    public void construtor_DeveRejeitarConfigNula()
    {
        var ex = Assert.Throws<ArgumentNullException>(
            () => new SmartTokenClient(new FakeSigningStrategy(), null!));

        Assert.Equal("faultTolerance", ex.ParamName);
    }

    [Fact]
    public void dispose_DeveSerIdempotenteEImpedirNovasOperacoes()
    {
        var client = new SmartTokenClient(new FakeSigningStrategy(), CreateDefaultFaultTolerance());

        client.Dispose();
        client.Dispose();

        Assert.Throws<ObjectDisposedException>(client.EnsureOpen);
    }

    [Fact]
    public async Task disposeAsync_DeveSerIdempotente()
    {
        var client = new SmartTokenClient(new FakeSigningStrategy(), CreateDefaultFaultTolerance());

        await client.DisposeAsync();
        await client.DisposeAsync();

        Assert.Throws<ObjectDisposedException>(client.EnsureOpen);
    }

    [Fact]
    public void signingStrategy_DeveRejeitarDadosNulos()
    {
        ISigningStrategy strategy = new FakeSigningStrategy();

        Assert.Throws<ArgumentNullException>(() => strategy.Sign(null!));
    }

    private static FaultToleranceConfig CreateDefaultFaultTolerance()
    {
        return new FaultToleranceConfig(
            SmartTokenClient.DefaultConnectTimeout,
            SmartTokenClient.DefaultRequestTimeout,
            SmartTokenClient.DefaultAssertionTtlSeconds,
            SmartTokenClient.DefaultMaxRetries);
    }
}

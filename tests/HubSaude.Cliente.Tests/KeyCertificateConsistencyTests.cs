// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using HubSaude.Cliente.Tests.Fakes;

namespace HubSaude.Cliente.Tests;

public sealed class KeyCertificateConsistencyTests : IDisposable
{
    private readonly RSA _rsa = CryptoFixtures.CreateRsa();
    private readonly RSA _otherRsa = CryptoFixtures.CreateRsa();
    private readonly ECDsa _ec = CryptoFixtures.CreateP256();

    public void Dispose()
    {
        _rsa.Dispose();
        _otherRsa.Dispose();
        _ec.Dispose();
    }

    [Fact]
    public void deveAceitarParRsaConsistente()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa);
        KeyCertificateConsistency.VerifyKeyPair(_rsa, cert);
    }

    [Fact]
    public void deveRejeitarParRsaInconsistente()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa);
        var ex = Assert.Throws<SmartTokenException>(() => KeyCertificateConsistency.VerifyKeyPair(_otherRsa, cert));
        Assert.Contains("n\u00e3o corresponde ao certificado", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveAceitarParEcConsistente()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_ec);
        KeyCertificateConsistency.VerifyKeyPair(_ec, cert);
    }

    [Fact]
    public void deveVerificarEstrategiaPrivateKey()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa);
        var strategy = new PrivateKeySigningStrategy(_rsa, "SHA384withRSA");
        KeyCertificateConsistency.VerifyStrategy(strategy, cert);
    }

    [Fact]
    public void deveIgnorarEstrategiaCustomizada()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa);
        KeyCertificateConsistency.VerifyStrategy(new FakeSigningStrategy(), cert);
    }

    [Fact]
    public void deveRejeitarEstrategiaDeOutraChave()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa);
        var strategy = new PrivateKeySigningStrategy(_otherRsa, "SHA384withRSA");
        Assert.Throws<SmartTokenException>(() => KeyCertificateConsistency.VerifyStrategy(strategy, cert));
    }

    [Fact]
    public void deveRejeitarTipoDeChaveNaoSuportado()
    {
        using var dsa = DSA.Create(2048);
        using var cert = CryptoFixtures.SelfSignedCert(_rsa);
        var ex = Assert.Throws<SmartTokenException>(() => KeyCertificateConsistency.VerifyKeyPair(dsa, cert));
        Assert.Contains("n\u00e3o suportado", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void desafioDeveSerOMesmoDoJava()
    {
        Assert.Equal("key-pair-consistency-check"u8.ToArray(), KeyCertificateConsistency.Challenge);
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente.Tests;

public sealed class Pkcs12KeyStorageTests : IDisposable
{
    private readonly RSA _rsa = CryptoFixtures.CreateRsa();
    private readonly ECDsa _ec = CryptoFixtures.CreateP256();

    public void Dispose()
    {
        _rsa.Dispose();
        _ec.Dispose();
    }

    [Fact]
    public void mtlsFlags_DevemSerCompativeisComAPlataforma()
    {
        var flags = Pkcs12KeyStorage.MtlsFlags();
        if (OperatingSystem.IsWindows())
        {
            Assert.True(flags.HasFlag(X509KeyStorageFlags.UserKeySet));
            Assert.True(flags.HasFlag(X509KeyStorageFlags.Exportable));
            return;
        }

        Assert.Equal(X509KeyStorageFlags.EphemeralKeySet, flags);
    }

    [Fact]
    public void fromKeyAndCertificate_DeveProduzirCertificadoComChaveRsa()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa, "cliente-rsa");
        using var mtls = Pkcs12KeyStorage.FromKeyAndCertificate(_rsa, cert);
        Assert.True(mtls.HasPrivateKey);
        using var rsa = mtls.GetRSAPrivateKey();
        Assert.NotNull(rsa);
        var data = "mtls-rsa"u8.ToArray();
        Assert.True(_rsa.VerifyData(
            data,
            rsa.SignData(data, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            HashAlgorithmName.SHA384,
            RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void fromKeyAndCertificate_DeveProduzirCertificadoComChaveEc()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_ec, "cliente-ec");
        using var mtls = Pkcs12KeyStorage.FromKeyAndCertificate(_ec, cert);
        Assert.True(mtls.HasPrivateKey);
        using var ecdsa = mtls.GetECDsaPrivateKey();
        Assert.NotNull(ecdsa);
    }

    [Fact]
    public void fromKeyAndCertificate_DeveRejeitarParInconsistente()
    {
        using var other = CryptoFixtures.CreateRsa();
        using var cert = CryptoFixtures.SelfSignedCert(_rsa, "cliente-rsa");
        var ex = Assert.Throws<SmartTokenException>(
            () => Pkcs12KeyStorage.FromKeyAndCertificate(other, cert));
        Assert.Contains("n\u00e3o corresponde", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void fromKeyAndCertificate_DeveRejeitarTipoNaoSuportado()
    {
        using var dsa = DSA.Create(2048);
        using var cert = CryptoFixtures.SelfSignedCert(_rsa);
        var ex = Assert.Throws<SmartTokenException>(
            () => Pkcs12KeyStorage.FromKeyAndCertificate(dsa, cert));
        Assert.Contains("n\u00e3o suportado para mTLS", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void loadCertificate_DeveSelecionarPeloCn()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa, "alias-cn");
        var pfx = cert.Export(X509ContentType.Pfx, "changeit");
        using var loaded = Pkcs12KeyStorage.LoadCertificate(pfx, "alias-cn", "changeit".ToCharArray());
        Assert.True(loaded.HasPrivateKey);
        Assert.True(Pkcs12KeyStorage.MatchesAlias(loaded, "alias-cn"));
    }

    [Fact]
    public void loadCertificate_DeveFalharComAliasInexistente()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa, "alias-cn");
        var pfx = cert.Export(X509ContentType.Pfx, "changeit");
        var ex = Assert.Throws<SmartTokenException>(
            () => Pkcs12KeyStorage.LoadCertificate(pfx, "outro", "changeit".ToCharArray()));
        Assert.Contains("Chave n\u00e3o encontrada", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void matchesAlias_DeveAceitarFriendlyNameQuandoDefinido()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa, "cn-diferente");
        Assert.True(Pkcs12KeyStorage.MatchesAlias(cert, "cn-diferente"));
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        cert.FriendlyName = "friendly-alias";
        Assert.True(Pkcs12KeyStorage.MatchesAlias(cert, "friendly-alias"));
        Assert.True(Pkcs12KeyStorage.MatchesAlias(cert, "cn-diferente"));
    }

    [Fact]
    public void loadCertificate_DeveRejeitarCertificadoExpirado()
    {
        var request = new CertificateRequest(
            "CN=alias-expirado",
            _rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(-1));
        var pfx = cert.Export(X509ContentType.Pfx, "changeit");
        var ex = Assert.Throws<SmartTokenException>(
            () => Pkcs12KeyStorage.LoadCertificate(pfx, "alias-expirado", "changeit".ToCharArray()));
        Assert.Contains("expirado", ex.Message, StringComparison.Ordinal);
    }
}

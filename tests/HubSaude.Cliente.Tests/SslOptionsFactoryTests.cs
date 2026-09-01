// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente.Tests;

public sealed class SslOptionsFactoryTests
{
    [Fact]
    public void parseProtocol_DeveMapearValoresSuportados()
    {
        Assert.Equal(SslProtocols.Tls13, SslOptionsFactory.ParseProtocol("TLSv1.3"));
        Assert.Equal(SslProtocols.Tls12, SslOptionsFactory.ParseProtocol("TLSv1.2"));
        Assert.Equal(SslProtocols.Tls12 | SslProtocols.Tls13, SslOptionsFactory.ParseProtocol("TLS"));
        var ex = Assert.Throws<SmartTokenException>(() => SslOptionsFactory.ParseProtocol("SSLv3"));
        Assert.Contains("Protocolo TLS n\u00e3o suportado", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void createHandler_DeveConfigurarTlsUnidirecionalSemMaterialDeCliente()
    {
        using var handler = SslOptionsFactory.CreateHandler(
            TimeSpan.FromSeconds(5),
            "TLSv1.3",
            serverTrustAnchor: null,
            clientCertificate: null);
        Assert.Equal(SslProtocols.Tls13, handler.SslOptions.EnabledSslProtocols);
        Assert.True(handler.SslOptions.ClientCertificates is null or { Count: 0 });
    }

    [Fact]
    public void createHandler_DeveRejeitarCertificadoDeClienteSemChave()
    {
        using var rsa = CryptoFixtures.CreateRsa();
        using var cert = X509Certificate2.CreateFromPem(CryptoFixtures.SelfSignedPem(
            rsa,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30)));
        var ex = Assert.Throws<SmartTokenException>(() => SslOptionsFactory.CreateHandler(
            TimeSpan.FromSeconds(5),
            "TLSv1.2",
            serverTrustAnchor: null,
            clientCertificate: cert));
        Assert.Contains("chave privada", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void createHandler_DeveApresentarCertificadoComChaveNoMtls()
    {
        using var rsa = CryptoFixtures.CreateRsa();
        using var cert = CryptoFixtures.SelfSignedCert(rsa);
        using var handler = SslOptionsFactory.CreateHandler(
            TimeSpan.FromSeconds(5),
            "TLSv1.2",
            serverTrustAnchor: null,
            clientCertificate: cert);
        Assert.Equal(SslProtocols.Tls12, handler.SslOptions.EnabledSslProtocols);
        Assert.NotNull(handler.SslOptions.ClientCertificates);
        Assert.Single(handler.SslOptions.ClientCertificates);
        Assert.NotNull(handler.SslOptions.LocalCertificateSelectionCallback);
        Assert.Same(
            cert,
            handler.SslOptions.LocalCertificateSelectionCallback!(
                null!,
                "localhost",
                handler.SslOptions.ClientCertificates,
                remoteCertificate: null,
                acceptableIssuers: []));
    }

    [Fact]
    public void createHandler_DeveValidarTrustAnchorExpirado()
    {
        using var rsa = CryptoFixtures.CreateRsa();
        using var expired = new CertificateRequest(
                "CN=expired",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30), DateTimeOffset.UtcNow.AddDays(-1));
        var ex = Assert.Throws<SmartTokenException>(() => SslOptionsFactory.CreateHandler(
            TimeSpan.FromSeconds(5),
            "TLSv1.3",
            expired,
            clientCertificate: null));
        Assert.Contains("expirado", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void configure_DeveRegistrarCallbackDeTrustAnchor()
    {
        using var rsa = CryptoFixtures.CreateRsa();
        using var anchor = CryptoFixtures.SelfSignedCert(rsa, "trust");
        var options = new SslClientAuthenticationOptions();
        SslOptionsFactory.Configure(options, "TLSv1.3", anchor, clientCertificate: null);
        Assert.NotNull(options.RemoteCertificateValidationCallback);
        Assert.True(options.RemoteCertificateValidationCallback(null!, anchor, null, SslPolicyErrors.None));
        Assert.False(options.RemoteCertificateValidationCallback(null!, null, null, SslPolicyErrors.None));
    }
}

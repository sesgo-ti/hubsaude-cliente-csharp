// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente.Tests;

/// <summary>
/// Resolução de certificado de cliente para mTLS (PEM materializado em PKCS#12).
/// Cobre a regressão do Schannel no Windows, que rejeita chave efêmera.
/// </summary>
public sealed class TlsSettingsTests : IDisposable
{
    private readonly RSA _rsa = CryptoFixtures.CreateRsa();

    public void Dispose()
    {
        _rsa.Dispose();
    }

    [Fact]
    public void resolveClientCertificate_DeveMaterializarPkcs12APartirDePem()
    {
        using var withKey = CryptoFixtures.SelfSignedCert(_rsa, "cliente-mtls");
        using var publicOnly = X509CertificateLoader.LoadCertificate(withKey.RawData);
        var tls = new TlsSettings();
        using var mtls = tls.ResolveClientCertificate(_rsa, publicOnly);
        Assert.NotNull(mtls);
        Assert.True(mtls.HasPrivateKey);
        Assert.NotSame(publicOnly, mtls);
        Assert.True(mtls.GetRSAPrivateKey() is not null);
    }

    [Fact]
    public void resolveClientCertificate_DevePreferirClientCertificateExplicito()
    {
        using var pemCert = CryptoFixtures.SelfSignedCert(_rsa, "pem");
        using var explicitCert = CryptoFixtures.SelfSignedCert(_rsa, "explicito");
        var tls = new TlsSettings();
        tls.SetClientCertificate(explicitCert);
        var resolved = tls.ResolveClientCertificate(_rsa, pemCert);
        Assert.Same(explicitCert, resolved);
    }

    [Fact]
    public void resolveClientCertificate_DeveRetornarNuloSemMaterial()
    {
        var tls = new TlsSettings();
        Assert.Null(tls.ResolveClientCertificate(null, null));
    }
}

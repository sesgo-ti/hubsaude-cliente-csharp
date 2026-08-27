// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente.Tests;

public sealed class CertificateValidatorTests : IDisposable
{
    private readonly RSA _rsa = CryptoFixtures.CreateRsa();
    private readonly List<string> _files = [];

    public void Dispose()
    {
        foreach (var file in _files)
        {
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }

        _rsa.Dispose();
    }

    [Fact]
    public void deveValidarCertificadoValido()
    {
        var path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.SelfSignedPem(
            _rsa, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30))));
        using var cert = CertificateValidator.ValidateFromPemFile(path);
        Assert.NotNull(cert);
        CertificateValidator.CheckValidity(cert, path);
    }

    [Fact]
    public void deveLancarExcecaoParaCertificadoExpirado()
    {
        var pem = CryptoFixtures.SelfSignedPem(
            _rsa, DateTimeOffset.UtcNow.AddDays(-10), DateTimeOffset.UtcNow.AddDays(-1));
        var path = Track(CryptoFixtures.WriteTemp(pem));
        var ex = Assert.Throws<SmartTokenException>(() => CertificateValidator.ValidateFromPemFile(path));
        Assert.Contains("Certificado expirado", ex.Message, StringComparison.Ordinal);
        Assert.Contains(path, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveLancarExcecaoParaCertificadoFuturo()
    {
        var pem = CryptoFixtures.SelfSignedPem(
            _rsa, DateTimeOffset.UtcNow.AddDays(2), DateTimeOffset.UtcNow.AddDays(30));
        var ex = Assert.Throws<SmartTokenException>(() => CertificateValidator.ValidateFromPem(pem, "futuro"));
        Assert.Contains("ainda n\u00e3o \u00e9 v\u00e1lido", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveLancarIoExceptionParaArquivoInexistente()
    {
        Assert.ThrowsAny<IOException>(
            () => CertificateValidator.ValidateFromPemFile(Path.Combine(Path.GetTempPath(), "nao-existe.pem")));
    }

    [Fact]
    public void deveLancarExcecaoParaConteudoNaoCertificado()
    {
        var ex = Assert.Throws<SmartTokenException>(
            () => CertificateValidator.ValidateFromPem("-----BEGIN PRIVATE KEY-----\nMAo=\n-----END PRIVATE KEY-----", "src"));
        Assert.Contains("n\u00e3o cont\u00e9m certificado", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarCertificadoNulo()
    {
        Assert.Throws<ArgumentNullException>(() => CertificateValidator.CheckValidity(null!, "src"));
    }

    private string Track(string path)
    {
        _files.Add(path);
        return path;
    }
}

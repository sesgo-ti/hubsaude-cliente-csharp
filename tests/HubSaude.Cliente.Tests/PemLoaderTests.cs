// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace HubSaude.Cliente.Tests;

public sealed class PemLoaderTests : IDisposable
{
    private readonly RSA _rsa = CryptoFixtures.CreateRsa();
    private readonly string _pkcs8Path;
    private readonly string _certPath;
    private readonly List<string> _tempFiles = [];

    public PemLoaderTests()
    {
        _pkcs8Path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.ToPkcs8Pem(_rsa)));
        _certPath = Track(CryptoFixtures.WriteTemp(
            CryptoFixtures.SelfSignedPem(_rsa, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30))));
    }

    public void Dispose()
    {
        foreach (var file in _tempFiles)
        {
            if (File.Exists(file))
            {
                File.Delete(file);
            }
        }

        _rsa.Dispose();
    }

    [Fact]
    public void deveCarregarChavePrivadaPkcs8()
    {
        using var loaded = PemLoader.LoadPrivateKey(_pkcs8Path);
        var rsa = Assert.IsAssignableFrom<RSA>(loaded);
        Assert.Equal(_rsa.KeySize, rsa.KeySize);
    }

    [Fact]
    public void deveCarregarChavePrivadaSemSenha()
    {
        using var loaded = PemLoader.LoadPrivateKey(_pkcs8Path, password: null);
        Assert.IsAssignableFrom<RSA>(loaded);
    }

    [Fact]
    public void deveCarregarCertificado()
    {
        using var cert = PemLoader.LoadCertificate(_certPath);
        Assert.NotNull(cert.GetRSAPublicKey());
    }

    [Fact]
    public void deveFalharComChaveInexistente()
    {
        Assert.ThrowsAny<IOException>(() => PemLoader.LoadPrivateKey(Path.Combine(Path.GetTempPath(), "nao-existe.pem")));
    }

    [Fact]
    public void deveFalharComCertificadoInexistente()
    {
        Assert.ThrowsAny<IOException>(
            () => PemLoader.LoadCertificate(Path.Combine(Path.GetTempPath(), "nao-existe.pem")));
    }

    [Fact]
    public void deveFalharComArquivoPemVazio()
    {
        var vazio = Track(CryptoFixtures.WriteTemp(string.Empty));
        var ex = Assert.Throws<SmartTokenException>(() => PemLoader.LoadPrivateKey(vazio));
        Assert.Contains("vazio ou inv\u00e1lido", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveFalharComArquivoPemInvalido()
    {
        var invalido = Track(CryptoFixtures.WriteTemp("conteudo invalido que nao eh PEM"));
        Assert.Throws<SmartTokenException>(() => PemLoader.LoadPrivateKey(invalido));
    }

    [Fact]
    public void deveFalharQuandoArquivoNaoContemChave()
    {
        var ex = Assert.Throws<SmartTokenException>(() => PemLoader.LoadPrivateKey(_certPath));
        Assert.Contains("n\u00e3o suportado", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveFalharQuandoArquivoNaoContemCertificado()
    {
        var ex = Assert.Throws<SmartTokenException>(() => PemLoader.LoadCertificate(_pkcs8Path));
        Assert.Contains("n\u00e3o cont\u00e9m certificado", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveCarregarChavePrivadaDeString()
    {
        using var loaded = PemLoader.LoadPrivateKeyFromString(File.ReadAllText(_pkcs8Path), null, "test");
        Assert.IsAssignableFrom<RSA>(loaded);
    }

    [Fact]
    public void deveCarregarCertificadoDeString()
    {
        using var cert = PemLoader.LoadCertificateFromString(File.ReadAllText(_certPath), "test");
        Assert.NotNull(cert);
    }

    [Fact]
    public void deveRejeitarCertificadoExpiradoAoCarregar()
    {
        var pem = CryptoFixtures.SelfSignedPem(
            _rsa, DateTimeOffset.UtcNow.AddDays(-3), DateTimeOffset.UtcNow.AddDays(-1));
        var ex = Assert.Throws<SmartTokenException>(() => PemLoader.LoadCertificateFromString(pem, "cert-expirado"));
        Assert.Contains("Certificado expirado", ex.Message, StringComparison.Ordinal);
        Assert.Contains("cert-expirado", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarCertificadoAindaNaoValidoAoCarregar()
    {
        var pem = CryptoFixtures.SelfSignedPem(
            _rsa, DateTimeOffset.UtcNow.AddDays(2), DateTimeOffset.UtcNow.AddDays(365));
        var ex = Assert.Throws<SmartTokenException>(() => PemLoader.LoadCertificateFromString(pem, "cert-futuro"));
        Assert.Contains("ainda n\u00e3o \u00e9 v\u00e1lido", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveLancarArgumentNullExceptionParaPathNull()
    {
        Assert.Throws<ArgumentNullException>(() => PemLoader.LoadPrivateKey(null!));
        Assert.Throws<ArgumentNullException>(() => PemLoader.LoadCertificate(null!));
    }

    [Fact]
    public void deveLancarArgumentNullExceptionParaPemStringNull()
    {
        Assert.Throws<ArgumentNullException>(() => PemLoader.LoadPrivateKeyFromString(null!, null, "test"));
        Assert.Throws<ArgumentNullException>(() => PemLoader.LoadCertificateFromString(null!, "test"));
    }

    [Fact]
    public void deveLimparSenhaAposUso()
    {
        var senha = "minha-senha-secreta".ToCharArray();
        PemLoader.ClearPassword(senha);
        Assert.All(senha, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void deveTratarSenhaNullSemFalha()
    {
        PemLoader.ClearPassword(null);
    }

    [Fact]
    public void deveTratarSenhaVaziaSemFalha()
    {
        PemLoader.ClearPassword([]);
    }

    [Fact]
    public void deveConsumirSenhaMesmoComChaveNaoCriptografada()
    {
        var senha = "senha-desnecessaria".ToCharArray();
        using var loaded = PemLoader.LoadPrivateKeyFromString(File.ReadAllText(_pkcs8Path), senha, "test");
        Assert.NotNull(loaded);
        Assert.All(senha, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void deveIncluirOrigemNasMensagensDeErro()
    {
        var keyEx = Assert.Throws<SmartTokenException>(
            () => PemLoader.LoadPrivateKeyFromString("conteudo sem PEM", null, "minha-origem"));
        Assert.Contains("minha-origem", keyEx.Message, StringComparison.Ordinal);

        var certEx = Assert.Throws<SmartTokenException>(
            () => PemLoader.LoadCertificateFromString("conteudo sem PEM", "origem-cert"));
        Assert.Contains("origem-cert", certEx.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveCarregarChavePKCS1RsaNaoCriptografada()
    {
        var path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.ToPkcs1Pem(_rsa)));
        using var loaded = PemLoader.LoadPrivateKey(path);
        Assert.IsAssignableFrom<RSA>(loaded);
    }

    [Fact]
    public void deveFalharQuandoChavePkcs8EncriptadaSemSenha()
    {
        var path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.ToEncryptedPkcs8Pem(_rsa, "senha123")));
        var ex = Assert.Throws<SmartTokenException>(() => PemLoader.LoadPrivateKey(path));
        Assert.Contains("requer senha", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveCarregarChavePkcs8EncriptadaComSenhaCorreta()
    {
        var path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.ToEncryptedPkcs8Pem(_rsa, "senha123")));
        using var loaded = PemLoader.LoadPrivateKey(path, "senha123".ToCharArray());
        Assert.IsAssignableFrom<RSA>(loaded);
    }

    [Fact]
    public void deveFalharComSenhaIncorretaEmChavePkcs8Encriptada()
    {
        var path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.ToEncryptedPkcs8Pem(_rsa, "senha123")));
        var ex = Assert.Throws<SmartTokenException>(() => PemLoader.LoadPrivateKey(path, "senha-errada".ToCharArray()));
        Assert.Contains("senha incorreta", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveFalharQuandoChaveOpenSslEncriptadaSemSenha()
    {
        var path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.ToOpenSslEncryptedPem(_rsa, "openssl123")));
        var ex = Assert.Throws<SmartTokenException>(() => PemLoader.LoadPrivateKey(path));
        Assert.Contains("requer senha", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveCarregarChaveOpenSslEncriptadaComSenhaCorreta()
    {
        var path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.ToOpenSslEncryptedPem(_rsa, "openssl123")));
        using var loaded = PemLoader.LoadPrivateKey(path, "openssl123".ToCharArray());
        Assert.IsAssignableFrom<RSA>(loaded);
    }

    [Fact]
    public void deveFalharComSenhaIncorretaEmChaveOpenSslEncriptada()
    {
        var path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.ToOpenSslEncryptedPem(_rsa, "openssl123")));
        var ex = Assert.Throws<SmartTokenException>(
            () => PemLoader.LoadPrivateKey(path, "senha-errada".ToCharArray()));
        Assert.Contains("senha incorreta", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveFalharComSenhaVaziaEmChaveOpenSslEncriptada()
    {
        var path = Track(CryptoFixtures.WriteTemp(CryptoFixtures.ToOpenSslEncryptedPem(_rsa, "openssl123")));
        var ex = Assert.Throws<SmartTokenException>(() => PemLoader.LoadPrivateKey(path, []));
        Assert.Contains("requer senha", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarChaveRsaMenorQue2048Bits()
    {
        using var weak = CryptoFixtures.CreateRsa(1024);
        var pem = CryptoFixtures.ToPkcs8Pem(weak);
        var ex = Assert.Throws<ArgumentException>(() => PemLoader.LoadPrivateKeyFromString(pem, null, "rsa-1024"));
        Assert.Contains("1024 bits", ex.Message, StringComparison.Ordinal);
        Assert.Contains("2048", ex.Message, StringComparison.Ordinal);
        Assert.Contains("rsa-1024", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveAceitarChaveEcP256()
    {
        using var ec = CryptoFixtures.CreateP256();
        using var loaded = PemLoader.LoadPrivateKeyFromString(CryptoFixtures.ToPkcs8Pem(ec), null, "ec-p256");
        Assert.IsAssignableFrom<ECDsa>(loaded);
    }

    [Fact]
    public void deveRejeitarChaveEcMenorQueP256()
    {
        ECDsa? weak = null;
        try
        {
            weak = ECDsa.Create(ECCurve.CreateFromFriendlyName("nistP192"));
        }
        catch (CryptographicException)
        {
            return;
        }
        catch (PlatformNotSupportedException)
        {
            return;
        }
        catch (ArgumentException)
        {
            return;
        }

        using (weak)
        {
            var pem = CryptoFixtures.ToPkcs8Pem(weak);
            var ex = Assert.Throws<ArgumentException>(() => PemLoader.LoadPrivateKeyFromString(pem, null, "ec-192"));
            Assert.Contains("192 bits", ex.Message, StringComparison.Ordinal);
            Assert.Contains("P-256", ex.Message, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void deveValidarTamanhoMinimoDeChaveDireta()
    {
        PemLoader.ValidateMinimumKeySize(_rsa, "rsa-2048");
    }

    [Fact]
    public void deveCarregarChavePrivadaDeCharsEZerarBuffer()
    {
        var pem = File.ReadAllText(_pkcs8Path).ToCharArray();
        using var loaded = PemLoader.LoadPrivateKeyFromChars(pem, null, "test-chars");
        Assert.IsAssignableFrom<RSA>(loaded);
        Assert.All(pem, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void deveZerarBufferPemMesmoEmCasoDeErro()
    {
        var pemInvalido = "conteudo invalido que nao eh PEM".ToCharArray();
        var senha = "senha-qualquer".ToCharArray();
        var ex = Assert.Throws<SmartTokenException>(
            () => PemLoader.LoadPrivateKeyFromChars(pemInvalido, senha, "erro-test"));
        Assert.Contains("erro-test", ex.Message, StringComparison.Ordinal);
        Assert.All(pemInvalido, c => Assert.Equal('\0', c));
        Assert.All(senha, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void deveZerarBufferPemQuandoChaveEncriptadaComSenhaErrada()
    {
        var pem = CryptoFixtures.ToEncryptedPkcs8Pem(_rsa, "senha123").ToCharArray();
        var senhaErrada = "senha-errada".ToCharArray();
        Assert.Throws<SmartTokenException>(() => PemLoader.LoadPrivateKeyFromChars(pem, senhaErrada, "enc-test"));
        Assert.All(pem, c => Assert.Equal('\0', c));
        Assert.All(senhaErrada, c => Assert.Equal('\0', c));
    }

    private string Track(string path)
    {
        _tempFiles.Add(path);
        return path;
    }
}

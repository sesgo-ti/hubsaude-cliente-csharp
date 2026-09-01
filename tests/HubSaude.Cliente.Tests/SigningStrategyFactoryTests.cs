// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HubSaude.Cliente.Tests;

public sealed class SigningStrategyFactoryTests : IDisposable
{
    private readonly RSA _rsa = CryptoFixtures.CreateRsa();
    private readonly string _keyPath;

    public SigningStrategyFactoryTests()
    {
        _keyPath = CryptoFixtures.WriteTemp(CryptoFixtures.ToPkcs8Pem(_rsa));
    }

    public void Dispose()
    {
        if (File.Exists(_keyPath))
        {
            File.Delete(_keyPath);
        }

        _rsa.Dispose();
    }

    [Fact]
    public void deveAssinarComChavePrivadaDireta()
    {
        var strategy = SigningStrategyFactory.FromPrivateKey(_rsa);
        var dados = Encoding.UTF8.GetBytes("dados para assinar");
        var assinatura = strategy.Sign(dados);
        Assert.True(_rsa.VerifyData(dados, assinatura, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void deveAceitarAlgoritmosJwtEmMinusculas()
    {
        Assert.Equal("SHA256withRSA", SigningStrategyFactory.JwtAlgorithmToJava("rs256"));
        Assert.Equal("SHA384withRSA", SigningStrategyFactory.JwtAlgorithmToJava("rs384"));
        Assert.Equal("SHA512withRSA", SigningStrategyFactory.JwtAlgorithmToJava("rs512"));
        Assert.Equal("RSASSA-PSS", SigningStrategyFactory.JwtAlgorithmToJava("ps256"));
        Assert.Equal("SHA256withECDSAinP1363Format", SigningStrategyFactory.JwtAlgorithmToJava("es256"));
        Assert.NotNull(SigningStrategyFactory.PssParameterSpecFor("ps384"));
    }

    [Fact]
    public void deveAssinarComAlgoritmoJwtEmMinusculas()
    {
        var strategy = SigningStrategyFactory.FromPrivateKeyForJwt(_rsa, "rs384");
        var dados = Encoding.UTF8.GetBytes("dados para assinar");
        var assinatura = strategy.Sign(dados);
        Assert.True(_rsa.VerifyData(dados, assinatura, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void deveAssinarComOverloadSemSenha()
    {
        var strategy = SigningStrategyFactory.FromPemFile(_keyPath);
        Assert.NotNull(strategy.Sign("overload sem senha"u8.ToArray()));
    }

    [Fact]
    public void deveAssinarComArquivoPemSemSenha()
    {
        var strategy = SigningStrategyFactory.FromPemFile(_keyPath, null);
        var dados = Encoding.UTF8.GetBytes("mensagem de teste");
        Assert.True(_rsa.VerifyData(dados, strategy.Sign(dados), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void deveAssinarComPemString()
    {
        var strategy = SigningStrategyFactory.FromPemString(File.ReadAllText(_keyPath), null);
        var dados = Encoding.UTF8.GetBytes("dados string pem");
        Assert.True(_rsa.VerifyData(dados, strategy.Sign(dados), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void deveFalharComArquivoPemInexistente()
    {
        Assert.ThrowsAny<IOException>(
            () => SigningStrategyFactory.FromPemFile(Path.Combine(Path.GetTempPath(), "nao-existe.pem"), null));
    }

    [Fact]
    public void deveFalharComChavePrivadaNula()
    {
        Assert.Throws<ArgumentNullException>(() => SigningStrategyFactory.FromPrivateKey((RSA)null!));
    }

    [Fact]
    public void deveFalharComPathNulo()
    {
        Assert.Throws<ArgumentNullException>(() => SigningStrategyFactory.FromPemFile(null!, null));
    }

    [Fact]
    public void deveFalharComPemStringNula()
    {
        Assert.Throws<ArgumentNullException>(() => SigningStrategyFactory.FromPemString(null!, null));
    }

    [Fact]
    public void estrategiasDevemSerIdempotentes()
    {
        var strategy = SigningStrategyFactory.FromPrivateKey(_rsa);
        var dados = Encoding.UTF8.GetBytes("dados idempotentes");
        Assert.Equal(strategy.Sign(dados), strategy.Sign(dados));
    }

    [Fact]
    public void deveUsarAlgoritmoRS384PorPadrao()
    {
        var strategy = SigningStrategyFactory.FromPrivateKey(_rsa);
        var dados = Encoding.UTF8.GetBytes("teste RS384");
        var assinatura = strategy.Sign(dados);
        Assert.True(_rsa.VerifyData(dados, assinatura, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
        Assert.False(_rsa.VerifyData(dados, assinatura, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void deveAssinarComChavePrivadaEAlgoritmoCustomizado()
    {
        var strategy = SigningStrategyFactory.FromPrivateKey(_rsa, "SHA256withRSA");
        var dados = Encoding.UTF8.GetBytes("teste SHA256");
        Assert.True(_rsa.VerifyData(dados, strategy.Sign(dados), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void deveFalharComAlgorithmNeNulo()
    {
        Assert.Throws<ArgumentNullException>(() => SigningStrategyFactory.FromPrivateKey(_rsa, null!));
    }

    [Fact]
    public void deveAssinarComPkcs12()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa, "test-alias");
        var pfx = cert.Export(X509ContentType.Pfx, "senha123");
        var strategy = SigningStrategyFactory.FromPkcs12(pfx, "test-alias", "senha123".ToCharArray());
        var dados = Encoding.UTF8.GetBytes("dados keystore");
        Assert.True(_rsa.VerifyData(dados, strategy.Sign(dados), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void deveAssinarComPkcs12DeArquivo()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa, "test-alias");
        var pfx = cert.Export(X509ContentType.Pfx, "senha123");
        var path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pfx");
        File.WriteAllBytes(path, pfx);
        try
        {
            var strategy = SigningStrategyFactory.FromPkcs12File(path, "test-alias", "senha123".ToCharArray());
            var dados = Encoding.UTF8.GetBytes("dados arquivo");
            Assert.True(_rsa.VerifyData(dados, strategy.Sign(dados), HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void devePreservarSenhaDoChamadorEmFromPkcs12()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa, "test-alias");
        var pfx = cert.Export(X509ContentType.Pfx, "senha123");
        var senha = "senha123".ToCharArray();
        _ = SigningStrategyFactory.FromPkcs12(pfx, "test-alias", senha);
        Assert.Equal("senha123".ToCharArray(), senha);
        _ = SigningStrategyFactory.FromPkcs12(pfx, "test-alias", senha);
        Assert.Equal("senha123".ToCharArray(), senha);
    }

    [Fact]
    public void devePreservarSenhaDoChamadorMesmoEmErroNoFromPkcs12()
    {
        var senha = "senha123".ToCharArray();
        Assert.Throws<SmartTokenException>(() => SigningStrategyFactory.FromPkcs12([], "alias-inexistente", senha));
        Assert.Equal("senha123".ToCharArray(), senha);
    }

    [Fact]
    public void deveFalharComAliasInexistenteNoKeyStore()
    {
        using var cert = CryptoFixtures.SelfSignedCert(_rsa, "test-alias");
        var pfx = cert.Export(X509ContentType.Pfx, "senha123");
        var ex = Assert.Throws<SmartTokenException>(
            () => SigningStrategyFactory.FromPkcs12(pfx, "alias-inexistente", "senha123".ToCharArray()));
        Assert.Contains("Chave n\u00e3o encontrada", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveFalharComPkcs12Nulo()
    {
        Assert.Throws<ArgumentNullException>(() => SigningStrategyFactory.FromPkcs12(null!, "alias", null));
    }

    [Fact]
    public void deveFalharComAliasNuloNoKeyStore()
    {
        Assert.Throws<ArgumentNullException>(() => SigningStrategyFactory.FromPkcs12([1], null!, null));
    }

    [Fact]
    public void deveMapearEsParaFormatoP1363()
    {
        Assert.Equal("SHA256withECDSAinP1363Format", SigningStrategyFactory.JwtAlgorithmToJava("ES256"));
        Assert.Equal("SHA384withECDSAinP1363Format", SigningStrategyFactory.JwtAlgorithmToJava("ES384"));
        Assert.Equal("SHA512withECDSAinP1363Format", SigningStrategyFactory.JwtAlgorithmToJava("ES512"));
    }

    [Fact]
    public void deveMapearPsParaRsassaPss()
    {
        Assert.Equal("RSASSA-PSS", SigningStrategyFactory.JwtAlgorithmToJava("PS256"));
        Assert.Equal("RSASSA-PSS", SigningStrategyFactory.JwtAlgorithmToJava("PS384"));
        Assert.Equal("RSASSA-PSS", SigningStrategyFactory.JwtAlgorithmToJava("PS512"));
    }

    [Fact]
    public void deveRejeitarAlgoritmoNone()
    {
        var none = Assert.Throws<SmartTokenException>(() => SigningStrategyFactory.JwtAlgorithmToJava("none"));
        Assert.Contains("n\u00e3o suportado", none.Message, StringComparison.Ordinal);
        var hs = Assert.Throws<SmartTokenException>(() => SigningStrategyFactory.JwtAlgorithmToJava("HS256"));
        Assert.Contains("n\u00e3o suportado", hs.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRetornarPssParameterSpecCorretoPorVariante()
    {
        var ps256 = SigningStrategyFactory.PssParameterSpecFor("PS256")!;
        Assert.Equal("SHA-256", ps256.DigestAlgorithm);
        Assert.Equal(32, ps256.SaltLength);
        var ps384 = SigningStrategyFactory.PssParameterSpecFor("PS384")!;
        Assert.Equal("SHA-384", ps384.DigestAlgorithm);
        Assert.Equal(48, ps384.SaltLength);
        var ps512 = SigningStrategyFactory.PssParameterSpecFor("PS512")!;
        Assert.Equal("SHA-512", ps512.DigestAlgorithm);
        Assert.Equal(64, ps512.SaltLength);
        Assert.Null(SigningStrategyFactory.PssParameterSpecFor("RS256"));
    }

    [Fact]
    public void fromPrivateKeyForJwtDeveAssinarEs256Verificavel()
    {
        using var ec = CryptoFixtures.CreateP256();
        var strategy = SigningStrategyFactory.FromPrivateKeyForJwt(ec, "ES256");
        var data = Encoding.UTF8.GetBytes("dados-teste");
        var signature = strategy.Sign(data);
        Assert.Equal(64, signature.Length);
        Assert.True(ec.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    }

    [Fact]
    public void fromPrivateKeyForJwtDeveAssinarPs256Verificavel()
    {
        var strategy = SigningStrategyFactory.FromPrivateKeyForJwt(_rsa, "PS256");
        var data = Encoding.UTF8.GetBytes("dados-teste");
        Assert.True(_rsa.VerifyData(data, strategy.Sign(data), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }
}

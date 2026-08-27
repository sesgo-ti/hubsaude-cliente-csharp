// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Security.Cryptography;
using System.Text;

namespace HubSaude.Cliente.Tests;

public sealed class PrivateKeySigningStrategyTests : IDisposable
{
    private readonly RSA _rsa = CryptoFixtures.CreateRsa();
    private readonly ECDsa _ec = CryptoFixtures.CreateP256();

    public void Dispose()
    {
        _rsa.Dispose();
        _ec.Dispose();
    }

    [Fact]
    public void deveAssinarComChaveRSA()
    {
        var strategy = new PrivateKeySigningStrategy(_rsa, "SHA384withRSA");
        var dados = Encoding.UTF8.GetBytes("mensagem para assinar");
        var assinatura = strategy.Sign(dados);
        Assert.True(assinatura.Length > 0);
        Assert.True(_rsa.VerifyData(dados, assinatura, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void deveAssinarComDiferentesAlgoritmosRSA()
    {
        var dados = Encoding.UTF8.GetBytes("dados de teste");
        var sig256 = new PrivateKeySigningStrategy(_rsa, "SHA256withRSA").Sign(dados);
        Assert.True(_rsa.VerifyData(dados, sig256, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        var sig512 = new PrivateKeySigningStrategy(_rsa, "SHA512withRSA").Sign(dados);
        Assert.True(_rsa.VerifyData(dados, sig512, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void deveFalharComChaveIncompativelComAlgoritmo()
    {
        var strategy = new PrivateKeySigningStrategy(_ec, "SHA384withRSA");
        var ex = Assert.Throws<SigningException>(() => strategy.Sign("dados"u8.ToArray()));
        Assert.Contains("Falha ao assinar dados", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveFalharComAlgoritmoInvalido()
    {
        var strategy = new PrivateKeySigningStrategy(_rsa, "AlgoritmoInexistente");
        Assert.Throws<SigningException>(() => strategy.Sign("dados"u8.ToArray()));
    }

    [Fact]
    public void deveFalharComChaveNula()
    {
        Assert.Throws<ArgumentNullException>(() => new PrivateKeySigningStrategy((RSA)null!, "SHA384withRSA"));
    }

    [Fact]
    public void deveFalharComAlgoritmoNulo()
    {
        Assert.Throws<ArgumentNullException>(() => new PrivateKeySigningStrategy(_rsa, null!));
    }

    [Fact]
    public void deveFalharComDadosNulos()
    {
        var strategy = new PrivateKeySigningStrategy(_rsa, "SHA384withRSA");
        Assert.Throws<ArgumentNullException>(() => strategy.Sign(null!));
    }

    [Fact]
    public void deveSerIdempotente()
    {
        var strategy = new PrivateKeySigningStrategy(_rsa, "SHA384withRSA");
        var dados = Encoding.UTF8.GetBytes("mesmos dados");
        Assert.Equal(strategy.Sign(dados), strategy.Sign(dados));
    }

    [Fact]
    public void deveAssinarDadosVazios()
    {
        var strategy = new PrivateKeySigningStrategy(_rsa, "SHA384withRSA");
        byte[] empty = [];
        var sig = strategy.Sign(empty);
        Assert.True(_rsa.VerifyData(empty, sig, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1));
    }
}

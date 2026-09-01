// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HubSaude.Cliente.Tests;

public sealed class ClientAssertionTests : IDisposable
{
    private const string TokenEndpoint = "https://localhost:8443/auth/token";
    private const string ClientId = "test-client";

    private readonly RSA _rsa = CryptoFixtures.CreateRsa();
    private readonly FaultToleranceConfig _config = new(
        SmartTokenClient.DefaultConnectTimeout,
        SmartTokenClient.DefaultRequestTimeout,
        SmartTokenClient.DefaultAssertionTtlSeconds,
        SmartTokenClient.DefaultMaxRetries);

    public void Dispose()
    {
        _rsa.Dispose();
    }

    [Fact]
    public void deveConstruirClientAssertionComCamposCorretos()
    {
        using var client = CreateClient();
        var assertion = client.BuildClientAssertion();
        var payload = ParsePayload(assertion);

        Assert.Equal(ClientId, payload.GetProperty("iss").GetString());
        Assert.Equal(ClientId, payload.GetProperty("sub").GetString());
        Assert.Equal(TokenEndpoint, payload.GetProperty("aud").GetString());
        Assert.False(string.IsNullOrWhiteSpace(payload.GetProperty("jti").GetString()));
        var iat = payload.GetProperty("iat").GetInt64();
        var exp = payload.GetProperty("exp").GetInt64();
        Assert.Equal(SmartTokenClient.DefaultAssertionTtlSeconds, exp - iat);
        AssertSignatureValid(assertion, _rsa, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1);
    }

    [Fact]
    public void deveGerarJtiUnicoPorClientAssertion()
    {
        using var client = CreateClient();
        var jti1 = ParsePayload(client.BuildClientAssertion()).GetProperty("jti").GetString();
        var jti2 = ParsePayload(client.BuildClientAssertion()).GetProperty("jti").GetString();
        Assert.False(string.IsNullOrWhiteSpace(jti1));
        Assert.NotEqual(jti1, jti2);
    }

    [Fact]
    public void deveUsarTresPartesBase64UrlSemPadding()
    {
        using var client = CreateClient();
        var parts = client.BuildClientAssertion().Split('.');
        Assert.Equal(3, parts.Length);
        Assert.All(parts, part =>
        {
            Assert.DoesNotContain('=', part);
            Assert.DoesNotContain('+', part);
            Assert.DoesNotContain('/', part);
        });
    }

    [Fact]
    public void naoDeveIncluirKidNoHeaderPorPadrao()
    {
        using var client = CreateClient();
        var header = ParseHeader(client.BuildClientAssertion());
        Assert.False(header.TryGetProperty("kid", out _));
        Assert.Equal("RS384", header.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.GetProperty("typ").GetString());
        Assert.Null(client.KeyId);
        Assert.Equal("RS384", client.JwtAlgorithm);
    }

    [Fact]
    public void deveIncluirKidNoHeaderQuandoConfigurado()
    {
        using var client = CreateClient(keyId: "minha-chave-1");
        var headerJson = HeaderJson(client.BuildClientAssertion());
        Assert.Contains("\"kid\":\"minha-chave-1\"", headerJson, StringComparison.Ordinal);
        Assert.Equal("minha-chave-1", client.KeyId);
    }

    [Fact]
    public void naoDeveIncluirKidQuandoKeyIdEmBranco()
    {
        using var client = CreateClient(keyId: "   ");
        var header = ParseHeader(client.BuildClientAssertion());
        Assert.False(header.TryGetProperty("kid", out _));
        Assert.Null(client.KeyId);
    }

    [Fact]
    public void deveIncluirHubCtxQuandoConfigurado()
    {
        using var client = CreateClient(hubCtxIg: "hemograma", hubCtxVersao: "0.0.1");
        var payloadJson = PayloadJson(client.BuildClientAssertion());
        Assert.Contains("\"hub_ctx\":{\"ig\":\"hemograma\",\"versao\":\"0.0.1\"}", payloadJson, StringComparison.Ordinal);
    }

    [Fact]
    public void naoDeveIncluirHubCtxPorPadrao()
    {
        using var client = CreateClient();
        var payloadJson = PayloadJson(client.BuildClientAssertion());
        Assert.DoesNotContain("\"hub_ctx\"", payloadJson, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarHubContextComFormatoInvalido()
    {
        var upper = Assert.Throws<ArgumentException>(() => SmartTokenClient.ValidateHubContext("Hemograma", "0.0.1"));
        Assert.Contains("ig", upper.Message, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => SmartTokenClient.ValidateHubContext("a", "0.0.1"));
        var shortSemver = Assert.Throws<ArgumentException>(() => SmartTokenClient.ValidateHubContext("hemograma", "1.2"));
        Assert.Contains("versao", shortSemver.Message, StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => SmartTokenClient.ValidateHubContext("hemograma", "1.2.3-rc.1"));
        Assert.Throws<ArgumentException>(() => SmartTokenClient.ValidateHubContext(null, "1.2.3"));
        Assert.Throws<ArgumentException>(() => SmartTokenClient.ValidateHubContext("hemograma", null));
    }

    [Fact]
    public void deveAceitarHubContextValido()
    {
        var ex = Record.Exception(() => SmartTokenClient.ValidateHubContext("hemograma", "0.0.1"));
        Assert.Null(ex);
    }

    [Fact]
    public void deveRejeitarAlgoritmoJwtInvalidoNaConstrucao()
    {
        var strategy = SigningStrategyFactory.FromPrivateKey(_rsa);
        var none = Assert.Throws<SmartTokenException>(
            () => new SmartTokenClient(strategy, _config, TokenEndpoint, ClientId, jwtAlgorithm: "none"));
        Assert.Contains("n\u00e3o suportado", none.Message, StringComparison.Ordinal);
        Assert.Throws<SmartTokenException>(
            () => new SmartTokenClient(strategy, _config, TokenEndpoint, ClientId, jwtAlgorithm: "HS256"));
    }

    [Fact]
    public void deveAssinarClientAssertionComEs256EmFormatoP1363()
    {
        using var ec = CryptoFixtures.CreateP256();
        var strategy = SigningStrategyFactory.FromPrivateKeyForJwt(ec, "ES256");
        using var client = new SmartTokenClient(
            strategy, _config, TokenEndpoint, ClientId, jwtAlgorithm: "ES256");
        var assertion = client.BuildClientAssertion();
        var parts = assertion.Split('.');
        var signature = Base64Url.DecodeFromChars(parts[2]);
        Assert.Equal(64, signature.Length);
        var data = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
        Assert.True(ec.VerifyData(
            data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.Equal(ClientId, ParsePayload(assertion).GetProperty("sub").GetString());
    }

    [Fact]
    public void deveAssinarClientAssertionComPs256()
    {
        var strategy = SigningStrategyFactory.FromPrivateKeyForJwt(_rsa, "PS256");
        using var client = new SmartTokenClient(
            strategy, _config, TokenEndpoint, ClientId, jwtAlgorithm: "PS256");
        var assertion = client.BuildClientAssertion();
        Assert.Contains("\"alg\":\"PS256\"", HeaderJson(assertion), StringComparison.Ordinal);
        AssertSignatureValid(assertion, _rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    [Fact]
    public void buildClientAssertion_DeveFalharAposDispose()
    {
        var client = CreateClient();
        client.Dispose();
        Assert.Throws<ObjectDisposedException>(() => client.BuildClientAssertion());
    }

    [Fact]
    public void deveUsarTtlCustomizadoEPadraoQuandoNaoPositivo()
    {
        using var custom = new SmartTokenClient(
            SigningStrategyFactory.FromPrivateKey(_rsa),
            new FaultToleranceConfig(
                SmartTokenClient.DefaultConnectTimeout,
                SmartTokenClient.DefaultRequestTimeout,
                120,
                SmartTokenClient.DefaultMaxRetries),
            TokenEndpoint,
            ClientId);
        var payload = ParsePayload(custom.BuildClientAssertion());
        Assert.Equal(120, payload.GetProperty("exp").GetInt64() - payload.GetProperty("iat").GetInt64());

        using var zero = new SmartTokenClient(
            SigningStrategyFactory.FromPrivateKey(_rsa),
            new FaultToleranceConfig(
                SmartTokenClient.DefaultConnectTimeout,
                SmartTokenClient.DefaultRequestTimeout,
                0,
                SmartTokenClient.DefaultMaxRetries),
            TokenEndpoint,
            ClientId);
        payload = ParsePayload(zero.BuildClientAssertion());
        Assert.Equal(
            SmartTokenClient.DefaultAssertionTtlSeconds,
            payload.GetProperty("exp").GetInt64() - payload.GetProperty("iat").GetInt64());
    }

    [Fact]
    public void deveEscaparCaracteresEspeciaisDoClientId()
    {
        const string special = "id\"com\\aspas";
        using var client = new SmartTokenClient(
            SigningStrategyFactory.FromPrivateKey(_rsa),
            _config,
            TokenEndpoint,
            special);
        var json = PayloadJson(client.BuildClientAssertion());
        Assert.Equal(special, ParsePayload(client.BuildClientAssertion()).GetProperty("iss").GetString());
        Assert.Equal(special, ParsePayload(client.BuildClientAssertion()).GetProperty("sub").GetString());
        using var doc = JsonDocument.Parse(json);
        Assert.True(json.Contains("\\u0022", StringComparison.Ordinal) || json.Contains("\\\"", StringComparison.Ordinal));
    }

    [Fact]
    public void deveConstruirClientAssertionConcorrentemente()
    {
        using var client = CreateClient();
        var assertions = Enumerable.Range(0, 32)
            .AsParallel()
            .Select(_ => client.BuildClientAssertion())
            .ToArray();
        Assert.Equal(32, assertions.Distinct().Count());
        Assert.All(assertions, a => Assert.Equal(3, a.Split('.').Length));
    }

    private SmartTokenClient CreateClient(
        string? keyId = null,
        string? hubCtxIg = null,
        string? hubCtxVersao = null)
    {
        return new SmartTokenClient(
            SigningStrategyFactory.FromPrivateKey(_rsa),
            _config,
            TokenEndpoint,
            ClientId,
            jwtAlgorithm: null,
            keyId,
            hubCtxIg,
            hubCtxVersao);
    }

    private static void AssertSignatureValid(
        string assertion,
        RSA rsa,
        HashAlgorithmName hash,
        RSASignaturePadding padding)
    {
        var parts = assertion.Split('.');
        var data = Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]);
        var signature = Base64Url.DecodeFromChars(parts[2]);
        Assert.True(rsa.VerifyData(data, signature, hash, padding));
    }

    private static string HeaderJson(string assertion)
    {
        return Encoding.UTF8.GetString(Base64Url.DecodeFromChars(assertion.Split('.')[0]));
    }

    private static string PayloadJson(string assertion)
    {
        return Encoding.UTF8.GetString(Base64Url.DecodeFromChars(assertion.Split('.')[1]));
    }

    private static JsonElement ParseHeader(string assertion)
    {
        return JsonDocument.Parse(HeaderJson(assertion)).RootElement.Clone();
    }

    private static JsonElement ParsePayload(string assertion)
    {
        return JsonDocument.Parse(PayloadJson(assertion)).RootElement.Clone();
    }
}

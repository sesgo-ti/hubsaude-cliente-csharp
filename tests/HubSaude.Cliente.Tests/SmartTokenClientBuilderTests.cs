// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using HubSaude.Cliente.Tests.Fakes;

namespace HubSaude.Cliente.Tests;

public sealed class SmartTokenClientBuilderTests : IDisposable
{
    private readonly string _keyFile;
    private readonly string _certFile;
    private readonly List<SmartTokenClient> _open = [];

    public SmartTokenClientBuilderTests()
    {
        using var rsa = CryptoFixtures.CreateRsa();
        _keyFile = CryptoFixtures.WriteTemp(CryptoFixtures.ToPkcs8Pem(rsa));
        _certFile = CryptoFixtures.WriteTemp(CryptoFixtures.SelfSignedPem(
            rsa,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30)));
    }

    public void Dispose()
    {
        foreach (var client in _open)
        {
            client.Dispose();
        }

        TryDelete(_keyFile);
        TryDelete(_certFile);
    }

    [Fact]
    public void deveExigirTokenEndpointOuFhirBase()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => SmartTokenClient.CreateBuilder()
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .Build());
        Assert.Contains("tokenEndpoint ou fhirBase", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarAmbosTokenEndpoints()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .FhirBase("https://fhir.example.com")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .Build());
        Assert.Contains("tokenEndpoint OU fhirBase", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveExigirClientId()
    {
        Assert.Throws<ArgumentNullException>(() => SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .PrivateKeyPem(_keyFile)
            .Build());
    }

    [Fact]
    public void deveExigirAssinaturaOuChave()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .Build());
        Assert.Contains("signingStrategy ou privateKeyPem", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarAmbosSigningStrategyEPrivateKeyPem()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .SigningStrategy(new FakeSigningStrategy())
            .Build());
        Assert.Contains("signingStrategy OU privateKeyPem", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarHttpNaoLocal()
    {
        var ex = Assert.Throws<ArgumentException>(() => SmartTokenClient.CreateBuilder()
            .TokenEndpoint("http://exemplo.com/token")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .Build());
        Assert.Contains("https", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarTetoDeCacheInvalido()
    {
        Assert.Throws<ArgumentException>(() => SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .TokenCacheMaxEntries(0)
            .Build());
    }

    [Fact]
    public void deveConstruirComPrivateKeyPemECertificado()
    {
        var client = Register(SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("builder-test-client")
            .PrivateKeyPem(_keyFile)
            .CertificatePem(_certFile)
            .JwtAlgorithm("RS384")
            .KeyId("kid-1")
            .HubContext("hemograma", "0.0.1")
            .ConnectTimeout(TimeSpan.FromSeconds(15))
            .RequestTimeout(TimeSpan.FromSeconds(60))
            .AssertionTtlSeconds(180)
            .MaxRetries(5)
            .EnableTokenCache(true)
            .TokenCacheMarginSeconds(45)
            .TokenCacheMaxEntries(10)
            .TlsProtocol("TLSv1.2")
            .Build());
        Assert.Equal("https://auth.example.com/token", client.TokenEndpoint);
        Assert.Equal("RS384", client.JwtAlgorithm);
        Assert.Equal("kid-1", client.KeyId);
        Assert.Contains(".", client.BuildClientAssertion(), StringComparison.Ordinal);
    }

    [Fact]
    public void deveConstruirComSigningStrategySemCertificado()
    {
        using var rsa = CryptoFixtures.CreateRsa();
        var client = Register(SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .SigningStrategy(SigningStrategyFactory.FromPrivateKey(rsa))
            .EnableTokenCache(false)
            .Build());
        Assert.NotNull(client.BuildClientAssertion());
    }

    [Fact]
    public void deveRetornarMesmaInstanciaDoBuilder()
    {
        var builder = SmartTokenClient.CreateBuilder();
        Assert.Same(builder, builder.TokenEndpoint("https://auth.example.com/token"));
        Assert.Same(builder, builder.FhirBase("http://localhost/fhir"));
        Assert.Same(builder, builder.ClientId("id"));
        Assert.Same(builder, builder.PrivateKeyPem(_keyFile));
        Assert.Same(builder, builder.CertificatePem(_certFile));
        Assert.Same(builder, builder.PrivateKeyPassword("test".ToCharArray()));
        Assert.Same(builder, builder.TlsProtocol("TLSv1.3"));
        Assert.Same(builder, builder.ConnectTimeout(TimeSpan.FromSeconds(5)));
        Assert.Same(builder, builder.RequestTimeout(TimeSpan.FromSeconds(10)));
        Assert.Same(builder, builder.AssertionTtlSeconds(300));
        Assert.Same(builder, builder.EnableTokenCache(true));
        Assert.Same(builder, builder.TokenCacheMarginSeconds(30));
        Assert.Same(builder, builder.TokenCacheMaxEntries(1_000));
        Assert.Same(builder, builder.MaxRetries(3));
        Assert.Same(builder, builder.ServerTrustAnchor(_certFile));
        Assert.Same(builder, builder.JwtAlgorithm("ES384"));
        Assert.Same(builder, builder.KeyId("k"));
        Assert.Same(builder, builder.HubContext("hemograma", "0.0.1"));
        Assert.Same(builder, builder.ClientPkcs12([1, 2, 3], "alias", "x".ToCharArray()));
    }

    [Fact]
    public async Task deveObterTokenEndpointViaDiscovery()
    {
        var expected = "https://hub.saude.go.gov.br/auth/token";
        var handler = new ScriptableHandler(request =>
        {
            Assert.Contains(".well-known/smart-configuration", request.RequestUri!.ToString(), StringComparison.Ordinal);
            Assert.True(request.Headers.TryGetValues("traceparent", out var values));
            Assert.Matches("^00-[0-9a-f]{32}-[0-9a-f]{16}-00$", values.Single());
            return ScriptableHandler.Json(HttpStatusCode.OK, "{\"token_endpoint\":\"" + expected + "\"}");
        });
        var client = Register(SmartTokenClient.CreateBuilder()
            .FhirBase("http://localhost/fhir")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .HttpMessageHandler(handler)
            .Build());
        Assert.Equal(expected, client.TokenEndpoint);
    }

    [Fact]
    public async Task discovery_DeveAceitarBarraFinalNaBase()
    {
        string? uri = null;
        var handler = new ScriptableHandler(request =>
        {
            uri = request.RequestUri!.ToString();
            return ScriptableHandler.Json(HttpStatusCode.OK, "{\"token_endpoint\":\"https://hub.saude.go.gov.br/auth/token\"}");
        });
        Register(SmartTokenClient.CreateBuilder()
            .FhirBase("http://localhost/fhir/")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .HttpMessageHandler(handler)
            .Build());
        Assert.Equal("http://localhost/fhir/.well-known/smart-configuration", uri);
        await Task.CompletedTask;
    }

    [Fact]
    public void discovery_DeveFalharSemTokenEndpoint()
    {
        var handler = new ScriptableHandler(
            _ => ScriptableHandler.Json(HttpStatusCode.OK, "{\"issuer\":\"https://x\"}"));
        var ex = Assert.Throws<SmartTokenException>(() => SmartTokenClient.CreateBuilder()
            .FhirBase("http://localhost/fhir")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .HttpMessageHandler(handler)
            .Build());
        Assert.Contains("token_endpoint", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void discovery_DeveFalharEmStatusNao200()
    {
        var handler = new ScriptableHandler(
            _ => ScriptableHandler.Json(HttpStatusCode.NotFound, "{\"error\":\"missing\"}"));
        var ex = Assert.Throws<SmartTokenException>(() => SmartTokenClient.CreateBuilder()
            .FhirBase("http://localhost/fhir")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .HttpMessageHandler(handler)
            .Build());
        Assert.Contains("404", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void discovery_DeveRejeitarHttpNaoLocalDescoberto()
    {
        var handler = new ScriptableHandler(
            _ => ScriptableHandler.Json(HttpStatusCode.OK, "{\"token_endpoint\":\"http://exemplo.com/auth/token\"}"));
        var ex = Assert.Throws<ArgumentException>(() => SmartTokenClient.CreateBuilder()
            .FhirBase("http://localhost/fhir")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .HttpMessageHandler(handler)
            .Build());
        Assert.Contains("https", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRejeitarProtocoloTlsInvalido()
    {
        var ex = Assert.Throws<SmartTokenException>(() => SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .TlsProtocol("SSLv3")
            .Build());
        Assert.Contains("Protocolo TLS", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void sslOptionsFactory_DeveRejeitarConfiarEmNadaSemCertificado()
    {
        Assert.Throws<SmartTokenException>(() => SslOptionsFactory.ParseProtocol("not-a-protocol"));
        Assert.Equal(SslProtocols.Tls13, SslOptionsFactory.ParseProtocol("TLSv1.3"));
        Assert.Equal(SslProtocols.Tls12, SslOptionsFactory.ParseProtocol("TLSv1.2"));
    }

    [Fact]
    public async Task obtainToken_ViaBuilderComHandler()
    {
        var handler = new ScriptableHandler(
            _ => ScriptableHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"via-builder\",\"expires_in\":60}"));
        var client = Register(SmartTokenClient.CreateBuilder()
            .TokenEndpoint("http://localhost/auth/token")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .HttpMessageHandler(handler)
            .Build());
        Assert.Equal("via-builder", await client.ObtainTokenAsync(null));
    }

    [Fact]
    public void discovery_DeveIncluirTraceIdEmErroHttp()
    {
        var handler = new ScriptableHandler(
            _ => ScriptableHandler.Json(HttpStatusCode.NotFound, "{\"error\":\"missing\"}"));
        var ex = Assert.Throws<SmartTokenException>(() => SmartTokenClient.CreateBuilder()
            .FhirBase("http://localhost/fhir")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .HttpMessageHandler(handler)
            .Build());
        Assert.Contains("traceId=", ex.Message, StringComparison.Ordinal);
        Assert.Contains("404", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveZerarSenhaPemAposBuild()
    {
        var senha = "senha-nao-usada".ToCharArray();
        Register(SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .PrivateKeyPassword(senha)
            .Build());
        Assert.All(senha, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void deveConstruirComClientPkcs12EZerarSenha()
    {
        using var rsa = CryptoFixtures.CreateRsa();
        using var cert = CryptoFixtures.SelfSignedCert(rsa, "test-alias");
        var pfx = cert.Export(X509ContentType.Pfx, "changeit");
        var pin = "changeit".ToCharArray();
        var client = Register(SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .ClientPkcs12(pfx, "test-alias", pin)
            .Build());
        Assert.Contains(".", client.BuildClientAssertion(), StringComparison.Ordinal);
        Assert.All(pin, c => Assert.Equal('\0', c));
    }

    [Fact]
    public void deveFalharQuandoChaveECertificadoNaoFormamPar()
    {
        using var other = CryptoFixtures.CreateRsa();
        var otherCert = CryptoFixtures.WriteTemp(CryptoFixtures.SelfSignedPem(
            other,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30)));
        try
        {
            var ex = Assert.Throws<SmartTokenException>(() => SmartTokenClient.CreateBuilder()
                .TokenEndpoint("https://auth.example.com/token")
                .ClientId("id")
                .PrivateKeyPem(_keyFile)
                .CertificatePem(otherCert)
                .Build());
            Assert.Contains("n\u00e3o corresponde", ex.Message, StringComparison.Ordinal);
        }
        finally
        {
            TryDelete(otherCert);
        }
    }

    [Fact]
    public void deveFalharComChavePemInexistente()
    {
        Assert.ThrowsAny<Exception>(() => SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .PrivateKeyPem(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".pem"))
            .Build());
    }

    [Fact]
    public void deveConstruirComSigningStrategyECertificado()
    {
        using var rsa = CryptoFixtures.CreateRsa();
        var certPath = CryptoFixtures.WriteTemp(CryptoFixtures.SelfSignedPem(
            rsa,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30)));
        try
        {
            var client = Register(SmartTokenClient.CreateBuilder()
                .TokenEndpoint("https://auth.example.com/token")
                .ClientId("id")
                .SigningStrategy(SigningStrategyFactory.FromPrivateKey(rsa))
                .CertificatePem(certPath)
                .Build());
            Assert.NotNull(client.BuildClientAssertion());
        }
        finally
        {
            TryDelete(certPath);
        }
    }

    [Fact]
    public void deveAplicarTtlEMargemPadraoQuandoNaoPositivos()
    {
        var client = Register(SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .AssertionTtlSeconds(-10)
            .TokenCacheMarginSeconds(0)
            .MaxRetries(0)
            .Build());
        var payload = System.Text.Encoding.UTF8.GetString(
            System.Buffers.Text.Base64Url.DecodeFromChars(client.BuildClientAssertion().Split('.')[1]));
        using var doc = System.Text.Json.JsonDocument.Parse(payload);
        Assert.Equal(
            SmartTokenClient.DefaultAssertionTtlSeconds,
            doc.RootElement.GetProperty("exp").GetInt64() - doc.RootElement.GetProperty("iat").GetInt64());
        Assert.Equal(SmartTokenClient.DefaultMaxRetries, client.FaultTolerance.MaxRetries);
    }

    [Fact]
    public void deveRejeitarClientPkcs12ComPem()
    {
        using var rsa = CryptoFixtures.CreateRsa();
        using var cert = CryptoFixtures.SelfSignedCert(rsa, "test-alias");
        var pfx = cert.Export(X509ContentType.Pfx, "changeit");
        var ex = Assert.Throws<InvalidOperationException>(() => SmartTokenClient.CreateBuilder()
            .TokenEndpoint("https://auth.example.com/token")
            .ClientId("id")
            .PrivateKeyPem(_keyFile)
            .ClientPkcs12(pfx, "test-alias", "changeit".ToCharArray())
            .Build());
        Assert.Contains("clientPkcs12", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void requireHttps_DeveAceitarLoopback()
    {
        SmartConfigurationDiscovery.RequireHttps("http://127.0.0.1:8080/token", "tokenEndpoint");
        SmartConfigurationDiscovery.RequireHttps("http://localhost/token", "tokenEndpoint");
        SmartConfigurationDiscovery.RequireHttps("https://hub.saude.go.gov.br/token", "tokenEndpoint");
    }

    private SmartTokenClient Register(SmartTokenClient client)
    {
        _open.Add(client);
        return client;
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
    }
}

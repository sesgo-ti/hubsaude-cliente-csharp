// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace HubSaude.Cliente.Tests;

public sealed class TokenResponseAndErrorTests
{
    [Fact]
    public void deveAssumirExpiresInPadraoQuandoAusente()
    {
        var parsed = SmartTokenClient.ParseTokenResponse(
            "{\"access_token\":\"abc123\",\"token_type\":\"Bearer\"}");
        Assert.Equal("abc123", parsed.AccessToken);
        Assert.Equal(3600, parsed.ExpiresIn);
        Assert.Contains("abc123", parsed.RawJson, StringComparison.Ordinal);
    }

    [Fact]
    public void deveIgnorarCamposDesconhecidosEExtrairAccessToken()
    {
        var json = "{\"access_token\":\"tok\",\"expires_in\":120,\"token_type\":\"Bearer\",\"foo\":1}";
        Assert.Equal("tok", SmartTokenClient.ExtractAccessToken(json));
        Assert.Equal(120, SmartTokenClient.ParseTokenResponse(json).ExpiresIn);
    }

    [Fact]
    public void deveRejeitarRespostaSemAccessToken()
    {
        var ex = Assert.Throws<SmartTokenException>(
            () => SmartTokenClient.ParseTokenResponse("{\"expires_in\":3600}"));
        Assert.Contains("access_token", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"access_token\":\"abc123\",\"expires_in\":-300}")]
    [InlineData("{\"access_token\":\"abc123\",\"expires_in\":0}")]
    [InlineData("{\"access_token\":\"abc123\",\"expires_in\":\"depois\"}")]
    public void deveRejeitarExpiresInInvalido(string json)
    {
        var ex = Assert.Throws<SmartTokenException>(() => SmartTokenClient.ParseTokenResponse(json));
        Assert.Contains("expires_in", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void deveNormalizarExpiresInAcimaDoTeto()
    {
        var parsed = SmartTokenClient.ParseTokenResponse(
            "{\"access_token\":\"abc123\",\"expires_in\":999999999}");
        Assert.Equal(TokenResponseGuard.MaxExpiresInSeconds, parsed.ExpiresIn);
    }

    [Fact]
    public void deveAceitarExpiresInNoTeto()
    {
        var parsed = SmartTokenClient.ParseTokenResponse(
            "{\"access_token\":\"abc123\",\"expires_in\":86400}");
        Assert.Equal(86400, parsed.ExpiresIn);
    }

    [Fact]
    public void tokenResponse_ToStringNaoExpoeSegredos()
    {
        var response = new SmartTokenClient.TokenResponse("segredo", 60, "{\"access_token\":\"segredo\"}");
        Assert.DoesNotContain("segredo", response.ToString(), StringComparison.Ordinal);
        Assert.Contains("[REDACTED]", response.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void sanitize_DeveTratarNuloTruncarERedigir()
    {
        Assert.Equal("<empty>", ErrorClassifier.SanitizeErrorResponse(null));
        var longResponse = new string('x', 600);
        var truncated = ErrorClassifier.SanitizeErrorResponse(longResponse);
        Assert.Equal(503, truncated.Length);
        Assert.EndsWith("...", truncated, StringComparison.Ordinal);

        var json = ErrorClassifier.SanitizeErrorResponse("{\"access_token\":\"segredo\"}");
        Assert.Contains("[REDACTED]", json, StringComparison.Ordinal);
        Assert.DoesNotContain("segredo", json, StringComparison.Ordinal);

        var form = ErrorClassifier.SanitizeErrorResponse("token=segredo&foo=1");
        Assert.Contains("token=[REDACTED]", form, StringComparison.Ordinal);
        Assert.DoesNotContain("segredo", form, StringComparison.Ordinal);
    }

    [Fact]
    public void deveRedigirTokenAntesDeTruncarRespostaGrande()
    {
        var body = "{\"access_token\":\"segredo-super-longo\"}" + new string('x', 600);
        var sanitized = ErrorClassifier.SanitizeErrorResponse(body);
        Assert.DoesNotContain("segredo-super-longo", sanitized, StringComparison.Ordinal);
        Assert.Contains("[REDACTED]", sanitized, StringComparison.Ordinal);
        Assert.EndsWith("...", sanitized, StringComparison.Ordinal);
        Assert.True(sanitized.Length <= 503);
    }

    [Fact]
    public void deveClassificarFalhasDeRedeComoTransitorias()
    {
        Assert.True(ErrorClassifier.IsTransientNetworkFailure(new TimeoutException("timeout")));
        Assert.True(ErrorClassifier.IsTransientNetworkFailure(new System.Net.Sockets.SocketException()));
        Assert.True(ErrorClassifier.IsTransientNetworkFailure(
            new HttpRequestException("HTTP/1.1 header parser received no bytes")));
        Assert.True(ErrorClassifier.IsTransientNetworkFailure(
            new HttpRequestException("falhou", new EndOfStreamException())));
        Assert.True(ErrorClassifier.IsTransientNetworkFailure(
            new HttpRequestException("reset", new System.Net.Sockets.SocketException())));
    }

    [Fact]
    public void naoDeveClassificarFalhasTlsOuGenericasComoTransitorias()
    {
        Assert.False(ErrorClassifier.IsTransientNetworkFailure(new HttpRequestException("erro generico de I/O")));
        Assert.False(ErrorClassifier.IsTransientNetworkFailure(new AuthenticationException("handshake falhou")));
        var ssl = new AuthenticationException("TLS abortado", new System.Net.Sockets.SocketException());
        Assert.False(ErrorClassifier.IsTransientNetworkFailure(new HttpRequestException("wrap", ssl)));
    }

    [Fact]
    public void deveIdentificarRejeicaoDeCertificadoDeCliente()
    {
        Assert.True(ErrorClassifier.IsLikelyClientCertificateRejection(new AuthenticationTagMismatchException()));
        Assert.True(ErrorClassifier.IsLikelyClientCertificateRejection(
            new HttpRequestException("TLS", new AuthenticationException("Tag mismatch!", new AuthenticationTagMismatchException()))));
        Assert.True(ErrorClassifier.IsLikelyClientCertificateRejection(
            new AuthenticationException("Received fatal alert: certificate_revoked")));
        Assert.True(ErrorClassifier.IsLikelyClientCertificateRejection(
            new HttpRequestException("Received fatal alert: bad_record_mac")));
        Assert.True(ErrorClassifier.IsLikelyClientCertificateRejection(
            new HttpRequestException("RECEIVED FATAL ALERT: BAD_RECORD_MAC")));
    }

    [Fact]
    public void naoDeveIdentificarValidacaoLocalDoServidorComoMtls()
    {
        Assert.False(ErrorClassifier.IsLikelyClientCertificateRejection(new HttpRequestException("Connection reset")));
        Assert.False(ErrorClassifier.IsLikelyClientCertificateRejection(
            new HttpRequestException("Generic TLS failure")));
        Assert.False(ErrorClassifier.IsLikelyClientCertificateRejection(null));
        var handshake = new AuthenticationException("PKIX path building failed");
        Assert.False(ErrorClassifier.IsLikelyClientCertificateRejection(new HttpRequestException("TLS failure", handshake)));
        Assert.False(ErrorClassifier.IsLikelyClientCertificateRejection(
            new AuthenticationException("PKIX path validation failed", new CryptographicException("certificate expired"))));
    }

    [Fact]
    public void httpFailure_DeveIncluirTraceIdCorpoSanitizadoERetryAfter()
    {
        var classifier = new ErrorClassifier("cliente-teste", "https://auth.example/token", NullLogger());
        var trace = TraceContext.Generate();
        var ex = classifier.HttpFailure(
            HttpStatusCode.Unauthorized,
            retryAfter: null,
            "{\"error\":\"invalid_client\"}",
            trace);
        Assert.Contains("HTTP 401", ex.Message, StringComparison.Ordinal);
        Assert.Contains("traceId=" + trace.TraceId, ex.Message, StringComparison.Ordinal);
        Assert.Contains("invalid_client", ex.Message, StringComparison.Ordinal);

        var redacted = classifier.HttpFailure(
            HttpStatusCode.BadRequest,
            null,
            "{\"access_token\":\"segredo\"}",
            trace);
        Assert.Contains("[REDACTED]", redacted.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("segredo", redacted.Message, StringComparison.Ordinal);

        var rate = classifier.HttpFailure(HttpStatusCode.TooManyRequests, "30", "{\"error\":\"slow_down\"}", trace);
        Assert.Contains("HTTP 429", rate.Message, StringComparison.Ordinal);
        Assert.Contains("(Retry-After: 30)", rate.Message, StringComparison.Ordinal);
        Assert.Contains("a decis", rate.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void retriableOrRethrow_DeveConverterMtlsEPropagarDemais()
    {
        var classifier = new ErrorClassifier("cliente-teste", "https://auth.example/token", NullLogger());
        var trace = TraceContext.Generate();
        var timeout = new TimeoutException("request timed out");
        Assert.Same(timeout, classifier.RetriableOrRethrow(timeout, trace));

        var generic = new HttpRequestException("disco cheio");
        Assert.Same(generic, Assert.Throws<HttpRequestException>(() => classifier.RetriableOrRethrow(generic, trace)));

        var mtls = new HttpRequestException("tls", new AuthenticationException("Received fatal alert: certificate_revoked"));
        var converted = Assert.Throws<SmartTokenException>(() => classifier.RetriableOrRethrow(mtls, trace));
        Assert.Contains("https://auth.example/token", converted.Message, StringComparison.Ordinal);
        Assert.Contains("certificado de cliente rejeitado", converted.Message, StringComparison.Ordinal);
        Assert.Same(mtls, converted.InnerException);
    }

    [Fact]
    public async Task deveRespeitarLimiteDoCorpoHttp()
    {
        var huge = new string('a', 100);
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(huge, System.Text.Encoding.UTF8),
        };
        response.Content.Headers.ContentLength = TokenResponseGuard.MaxResponseBodyBytes + 1;
        var ex = await Assert.ThrowsAsync<SmartTokenException>(
            () => TokenResponseGuard.ReadBoundedStringAsync(response, TokenResponseGuard.MaxResponseBodyBytes, CancellationToken.None));
        Assert.Contains("excede o limite", ex.Message, StringComparison.Ordinal);
    }

    private static Microsoft.Extensions.Logging.ILogger NullLogger()
    {
        return Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;
    }
}

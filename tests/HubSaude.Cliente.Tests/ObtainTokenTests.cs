// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using HubSaude.Cliente.Tests.Fakes;

namespace HubSaude.Cliente.Tests;

public sealed class ObtainTokenTests : IDisposable
{
    private const string Endpoint = "http://localhost/auth/token";
    private const string ClientId = "test-client";
    private readonly RSA _rsa = CryptoFixtures.CreateRsa();

    public void Dispose()
    {
        _rsa.Dispose();
    }

    [Fact]
    public async Task deveObterTokenEmHttp200()
    {
        var handler = new ScriptableHandler(_ => ScriptableHandler.Json(
            HttpStatusCode.OK,
            "{\"access_token\":\"tok-ok\",\"expires_in\":3600,\"token_type\":\"Bearer\"}"));
        using var client = CreateClient(handler);
        var token = await client.ObtainTokenAsync("system/Patient.rs");
        Assert.Equal("tok-ok", token);
        Assert.Equal(1, handler.Calls);
        Assert.Contains("traceparent", handler.Requests[0].Headers.Select(h => h.Key), StringComparer.OrdinalIgnoreCase);
        Assert.Contains("grant_type=client_credentials", handler.Bodies[0], StringComparison.Ordinal);
        Assert.Contains("scope=system%2FPatient.rs", handler.Bodies[0], StringComparison.Ordinal);
    }

    [Fact]
    public async Task deveServirDoCacheNaSegundaChamada()
    {
        var handler = new ScriptableHandler(_ => ScriptableHandler.Json(
            HttpStatusCode.OK,
            "{\"access_token\":\"tok-cache\",\"expires_in\":3600}"));
        using var client = CreateClient(handler);
        var first = await client.ObtainTokenResponseAsync("system/Patient.rs");
        var second = await client.ObtainTokenResponseAsync(" system/Patient.rs ");
        Assert.Equal("tok-cache", first.AccessToken);
        Assert.NotNull(first.RawJson);
        Assert.Equal("tok-cache", second.AccessToken);
        Assert.Null(second.RawJson);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task cacheDesabilitado_DeveSempreIrARede()
    {
        var handler = new ScriptableHandler(_ => ScriptableHandler.Json(
            HttpStatusCode.OK,
            "{\"access_token\":\"tok\",\"expires_in\":3600}"));
        using var client = CreateClient(handler, enableCache: false);
        await client.ObtainTokenAsync("s");
        await client.ObtainTokenAsync("s");
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task invalidateCache_DeveForcarNovaObtencao()
    {
        var handler = new ScriptableHandler(_ => ScriptableHandler.Json(
            HttpStatusCode.OK,
            "{\"access_token\":\"tok\",\"expires_in\":3600}"));
        using var client = CreateClient(handler);
        await client.ObtainTokenAsync("a");
        client.InvalidateCache("a");
        await client.ObtainTokenAsync("a");
        client.InvalidateCache();
        await client.ObtainTokenAsync("a");
        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task naoDeveFazerRetryEmHttpDiferenteDeTimeout()
    {
        var handler = new ScriptableHandler(_ => ScriptableHandler.Json(
            HttpStatusCode.BadRequest,
            "{\"error\":\"invalid_client\",\"access_token\":\"segredo\"}"));
        using var client = CreateClient(handler, maxRetries: 3, delay: (_, _) => Task.CompletedTask);
        var ex = await Assert.ThrowsAsync<SmartTokenException>(() => client.ObtainTokenAsync("s"));
        Assert.Contains("HTTP 400", ex.Message, StringComparison.Ordinal);
        Assert.Contains("[REDACTED]", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("segredo", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task http429_DeveFalharSemRetryEIncluirRetryAfter()
    {
        var handler = new ScriptableHandler(_ => ScriptableHandler.Json(
            HttpStatusCode.TooManyRequests,
            "{\"error\":\"slow_down\"}",
            retryAfter: "30"));
        using var client = CreateClient(handler, delay: (_, _) => Task.CompletedTask);
        var ex = await Assert.ThrowsAsync<SmartTokenException>(() => client.ObtainTokenAsync("s"));
        Assert.Contains("HTTP 429", ex.Message, StringComparison.Ordinal);
        Assert.Contains("Retry-After: 30", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task deveRetentarEmFalhaTransitoriaEObterNaSegundaTentativa()
    {
        var calls = 0;
        var delays = new List<TimeSpan>();
        var handler = new ScriptableHandler((_, _) =>
        {
            calls++;
            if (calls == 1)
            {
                throw new HttpRequestException("Connection refused", new SocketException((int)SocketError.ConnectionRefused));
            }

            return Task.FromResult(ScriptableHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"tok-apos-timeout\",\"expires_in\":3600}"));
        });
        using var client = CreateClient(handler, delay: (d, _) =>
        {
            delays.Add(d);
            return Task.CompletedTask;
        });
        var token = await client.ObtainTokenAsync("s");
        Assert.Equal("tok-apos-timeout", token);
        Assert.Equal(2, handler.Calls);
        Assert.Equal([TimeSpan.FromSeconds(1)], delays);
    }

    [Fact]
    public async Task deveEsgotarRetriesEmFalhaTransitoria()
    {
        var delays = new List<TimeSpan>();
        var handler = new ScriptableHandler(
            (_, _) => throw new TimeoutException("request timed out"));
        using var client = CreateClient(handler, maxRetries: 3, delay: (d, _) =>
        {
            delays.Add(d);
            return Task.CompletedTask;
        });
        var ex = await Assert.ThrowsAsync<SmartTokenException>(() => client.ObtainTokenAsync("s"));
        Assert.Contains("3 tentativas", ex.Message, StringComparison.Ordinal);
        Assert.Equal(3, handler.Calls);
        Assert.Equal([TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(2)], delays);
    }

    [Fact]
    public async Task singleFlight_DeveDispararUmaRequisicaoPorScope()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new ScriptableHandler(async (_, ct) =>
        {
            started.TrySetResult();
            await release.Task.WaitAsync(ct).ConfigureAwait(false);
            return ScriptableHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"shared\",\"expires_in\":3600}");
        });
        using var client = CreateClient(handler);
        var t1 = client.ObtainTokenAsync("same");
        var t2 = client.ObtainTokenAsync("same");
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.Delay(50);
        Assert.Equal(1, handler.Calls);
        release.TrySetResult();
        var tokens = await Task.WhenAll(t1, t2);
        Assert.Equal("shared", tokens[0]);
        Assert.Equal("shared", tokens[1]);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task obtainToken_DeveFalharAposDispose()
    {
        using var client = CreateClient(new ScriptableHandler(
            _ => ScriptableHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"x\",\"expires_in\":1}")));
        client.Dispose();
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.ObtainTokenAsync("s"));
    }

    [Fact]
    public async Task cancellation_DeveSerPropagado()
    {
        using var cts = new CancellationTokenSource();
        var handler = new ScriptableHandler(async (_, ct) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
            return ScriptableHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"x\",\"expires_in\":1}");
        });
        using var client = CreateClient(handler);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.ObtainTokenAsync("s", cts.Token));
    }

    [Fact]
    public async Task scopesDistintos_DevemSerIndependentes()
    {
        var handler = new ScriptableHandler(request =>
        {
            var body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            var token = body.Contains("Patient", StringComparison.Ordinal) ? "tok-p" : "tok-o";
            return ScriptableHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"" + token + "\",\"expires_in\":3600}");
        });
        using var client = CreateClient(handler);
        Assert.Equal("tok-p", await client.ObtainTokenAsync("system/Patient.rs"));
        Assert.Equal("tok-o", await client.ObtainTokenAsync("system/Observation.rs"));
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task deveRenovarQuandoTokenEstaDentroDaMargem()
    {
        var handler = new ScriptableHandler(_ => ScriptableHandler.Json(
            HttpStatusCode.OK,
            "{\"access_token\":\"tok\",\"expires_in\":10}"));
        using var client = CreateClient(handler, tokenCacheMarginSeconds: 30);
        await client.ObtainTokenAsync("s");
        await client.ObtainTokenAsync("s");
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task deveOmitirScopeNuloETrimadoNoFormBodyHttp()
    {
        var handler = new ScriptableHandler(_ => ScriptableHandler.Json(
            HttpStatusCode.OK,
            "{\"access_token\":\"t\",\"expires_in\":3600}"));
        using var client = CreateClient(handler);
        await client.ObtainTokenAsync(null);
        await client.ObtainTokenAsync("  ");
        Assert.All(handler.Bodies, body => Assert.DoesNotContain("scope=", body, StringComparison.Ordinal));
        Assert.Equal("application/x-www-form-urlencoded", handler.Requests[0].Content!.Headers.ContentType!.MediaType);
        Assert.Null(handler.Requests[0].Content!.Headers.ContentType!.CharSet);
    }

    [Fact]
    public async Task deveEnviarTraceparentW3cENovoPorTentativa()
    {
        var calls = 0;
        var handler = new ScriptableHandler((_, _) =>
        {
            calls++;
            if (calls < 3)
            {
                throw new TimeoutException("timeout");
            }

            return Task.FromResult(ScriptableHandler.Json(
                HttpStatusCode.OK,
                "{\"access_token\":\"t\",\"expires_in\":3600}"));
        });
        using var client = CreateClient(handler, delay: (_, _) => Task.CompletedTask);
        await client.ObtainTokenAsync("s");
        var parents = handler.Requests
            .Select(r => r.Headers.GetValues("traceparent").Single())
            .ToArray();
        Assert.Equal(3, parents.Length);
        Assert.All(parents, p => Assert.Matches("^00-[0-9a-f]{32}-[0-9a-f]{16}-00$", p));
        Assert.Equal(parents.Distinct().Count(), parents.Length);
    }

    [Fact]
    public async Task deveFalharImediatamenteEm503SemRetry()
    {
        var handler = new ScriptableHandler(
            _ => ScriptableHandler.Json(HttpStatusCode.ServiceUnavailable, "{\"error\":\"down\"}"));
        using var client = CreateClient(handler, delay: (_, _) => Task.CompletedTask);
        var ex = await Assert.ThrowsAsync<SmartTokenException>(() => client.ObtainTokenAsync("s"));
        Assert.Contains("HTTP 503", ex.Message, StringComparison.Ordinal);
        Assert.Contains("traceId=", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task deveExporRawJsonNaPrimeiraResposta()
    {
        var json = "{\"access_token\":\"tok-raw\",\"expires_in\":3600}";
        var handler = new ScriptableHandler(_ => ScriptableHandler.Json(HttpStatusCode.OK, json));
        using var client = CreateClient(handler);
        var first = await client.ObtainTokenResponseAsync("s");
        Assert.Equal(json, first.RawJson);
        Assert.Equal("tok-raw", first.AccessToken);
    }

    [Fact]
    public async Task singleFlight_DeveColapsarOitoChamadas()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new ScriptableHandler(async (_, ct) =>
        {
            started.TrySetResult();
            await release.Task.WaitAsync(ct).ConfigureAwait(false);
            return ScriptableHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"shared8\",\"expires_in\":3600}");
        });
        using var client = CreateClient(handler);
        var tasks = Enumerable.Range(0, 8).Select(_ => client.ObtainTokenAsync("same")).ToArray();
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        release.TrySetResult();
        var tokens = await Task.WhenAll(tasks);
        Assert.All(tokens, t => Assert.Equal("shared8", t));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task dispose_DeveEsperarRequisicaoEmVooELimparCache()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new ScriptableHandler(async (_, ct) =>
        {
            started.TrySetResult();
            await release.Task.WaitAsync(ct).ConfigureAwait(false);
            return ScriptableHandler.Json(HttpStatusCode.OK, "{\"access_token\":\"in-flight\",\"expires_in\":3600}");
        });
        var client = CreateClient(handler);
        var obtain = client.ObtainTokenAsync("s");
        await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var disposing = client.DisposeAsync().AsTask();
        await Task.Delay(80);
        Assert.False(disposing.IsCompleted);
        release.TrySetResult();
        Assert.Equal("in-flight", await obtain);
        await disposing;
        Assert.Equal(0, client.TokenCacheSize);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.ObtainTokenAsync("s"));
    }

    [Fact]
    public async Task deveAbortarCorpoSemContentLengthAcimaDoLimite()
    {
        var handler = new ScriptableHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new OversizedStreamContent(),
        });
        using var client = CreateClient(handler);
        var ex = await Assert.ThrowsAsync<SmartTokenException>(() => client.ObtainTokenAsync("s"));
        Assert.Contains("excede o limite", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task mtlsHeuristic_DeveFalharSemRetryNoObtain()
    {
        var handler = new ScriptableHandler(
            (_, _) => throw new System.Security.Authentication.AuthenticationException(
                "Received fatal alert: certificate_revoked"));
        using var client = CreateClient(handler, delay: (_, _) => Task.CompletedTask);
        var ex = await Assert.ThrowsAsync<SmartTokenException>(() => client.ObtainTokenAsync("s"));
        Assert.Contains("certificado de cliente rejeitado", ex.Message, StringComparison.Ordinal);
        Assert.Equal(1, handler.Calls);
    }

    private SmartTokenClient CreateClient(
        HttpMessageHandler handler,
        bool enableCache = true,
        int maxRetries = 3,
        Func<TimeSpan, CancellationToken, Task>? delay = null,
        int tokenCacheMarginSeconds = SmartTokenClient.DefaultTokenCacheMarginSeconds)
    {
        var config = new FaultToleranceConfig(
            SmartTokenClient.DefaultConnectTimeout,
            SmartTokenClient.DefaultRequestTimeout,
            SmartTokenClient.DefaultAssertionTtlSeconds,
            maxRetries);
        return new SmartTokenClient(
            SigningStrategyFactory.FromPrivateKey(_rsa),
            config,
            Endpoint,
            ClientId,
            httpHandler: handler,
            delayAsync: delay,
            enableTokenCache: enableCache,
            tokenCacheMarginSeconds: tokenCacheMarginSeconds);
    }

    private sealed class OversizedStreamContent : HttpContent
    {
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context)
        {
            return SerializeToStreamAsync(stream, context, CancellationToken.None);
        }

        protected override async Task SerializeToStreamAsync(
            Stream stream,
            System.Net.TransportContext? context,
            CancellationToken cancellationToken)
        {
            var chunk = new byte[8192];
            Array.Fill(chunk, (byte)'a');
            for (var i = 0; i < 140; i++)
            {
                await stream.WriteAsync(chunk, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}

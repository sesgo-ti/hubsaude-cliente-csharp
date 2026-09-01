// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Extensions.Logging;

namespace HubSaude.Cliente;

public sealed partial class SmartTokenClient
{
    /// <summary>
    /// Obtém a resposta completa do token endpoint, com cache, single-flight e retry (RF-03 a RF-07).
    /// </summary>
    public async Task<TokenResponse> ObtainTokenResponseAsync(
        string? scope,
        CancellationToken cancellationToken = default)
    {
        BeginOperation();
        try
        {
            EnsureOpen();
            var normalizedScope = NormalizeScope(scope);
            var early = _tokenCache.CachedResponseIfValid(normalizedScope);
            if (early is not null)
            {
                return early;
            }

            return await FetchTokenWithRetryAsync(normalizedScope, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            EndOperation();
        }
    }

    private async Task<TokenResponse> FetchTokenWithRetryAsync(
        string normalizedScope,
        CancellationToken cancellationToken)
    {
        var gate = _tokenCache.LockFor(normalizedScope);
        _logger.LogDebug(
            "Iniciando obten\u00e7\u00e3o de token para clientId={ClientId} scope={Scope}",
            ClientId,
            normalizedScope);

        var maxRetries = FaultTolerance.MaxRetries;
        Exception? lastException = null;
        TraceContext? lastTrace = null;
        for (var attempt = 1; attempt <= maxRetries; attempt++)
        {
            var trace = TraceContext.Generate();
            lastTrace = trace;
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                var cached = _tokenCache.CachedResponseIfValid(normalizedScope);
                if (cached is not null)
                {
                    return cached;
                }

                return await DoObtainTokenAsync(normalizedScope, trace, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (SmartTokenException)
            {
                throw;
            }
            catch (Exception ex)
            {
                lastException = _errorClassifier.RetriableOrRethrow(ex, trace);
            }
            finally
            {
                gate.Release();
            }

            await WaitBeforeNextAttemptAsync(attempt, maxRetries, lastException, trace, cancellationToken)
                .ConfigureAwait(false);
        }

        throw new SmartTokenException(
            "Falha ap\u00f3s " + maxRetries + " tentativas (\u00faltimo traceId="
            + (lastTrace is not null ? lastTrace.TraceId : "n/d") + "): "
            + (lastException is not null ? lastException.Message : "sem causa capturada"),
            lastException);
    }

    private async Task WaitBeforeNextAttemptAsync(
        int attempt,
        int maxRetries,
        Exception? lastException,
        TraceContext trace,
        CancellationToken cancellationToken)
    {
        if (attempt >= maxRetries)
        {
            _logger.LogError(
                "Todas as {MaxRetries} tentativas falharam para clientId={ClientId} traceId={TraceId}",
                maxRetries,
                ClientId,
                trace.TraceId);
            return;
        }

        var delay = RetryPolicy.ComputeRetryDelay(attempt);
        _logger.LogWarning(
            "Tentativa {Attempt}/{MaxRetries} falhou para clientId={ClientId} traceId={TraceId}: {Error}. Retry em {DelayMs}ms",
            attempt,
            maxRetries,
            ClientId,
            trace.TraceId,
            lastException is not null ? lastException.Message : "sem causa capturada",
            (int)delay.TotalMilliseconds);
        await _delayAsync(delay, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TokenResponse> DoObtainTokenAsync(
        string scope,
        TraceContext trace,
        CancellationToken cancellationToken)
    {
        var assertion = BuildClientAssertion();
        var body = BuildFormBody(ClientId, assertion, scope);
        using var content = new StringContent(body, Encoding.UTF8);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");
        using var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint)
        {
            Content = content,
        };
        request.Headers.TryAddWithoutValidation(TraceContext.TraceparentHeader, trace.Traceparent);

        HttpResponseMessage response;
        try
        {
            response = await _httpClient
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw TokenResponseGuard.UnwrapBodyLimitViolation(ex);
        }

        using (response)
        {
            string responseBody;
            try
            {
                responseBody = await TokenResponseGuard
                    .ReadBoundedStringAsync(response, TokenResponseGuard.MaxResponseBodyBytes, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                throw TokenResponseGuard.UnwrapBodyLimitViolation(ex);
            }

            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw _errorClassifier.HttpFailure(
                    response.StatusCode,
                    GetRetryAfterRaw(response.Headers),
                    responseBody,
                    trace);
            }

            var tokenResponse = ParseTokenResponse(responseBody, _logger);
            _tokenCache.Store(scope, tokenResponse);
            _logger.LogInformation("Token obtido com sucesso para clientId={ClientId}", ClientId);
            return tokenResponse;
        }
    }

    private static string? GetRetryAfterRaw(HttpResponseHeaders headers)
    {
        if (headers.TryGetValues("Retry-After", out var values))
        {
            return values.FirstOrDefault();
        }

        return null;
    }
}
